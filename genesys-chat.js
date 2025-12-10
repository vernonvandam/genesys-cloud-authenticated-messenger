
// genesys-chat.js
// Authenticated Messenger with Auth0 (Authorization Code + PKCE)
// - Opens Messenger only after both Messenger.ready and Auth.authenticated.
// - getAuthCode returns { authCode, redirectUri, codeVerifier } as required.
// - No import.meta; reads Auth0 values from window.__ENV.
//
// Official Documentation:
// - https://developer.genesys.cloud/commdigital/digital/webmessaging/authenticate
// - https://help.mypurecloud.com/articles/get-started-with-authenticated-web-messaging/

class GenesysChatManager {
  constructor() {
    this.config = null;
    this.genesysReady = false;

    // Primary SPA client (optional)
    this.auth0Client = null;

    // Auth0 values used by Genesys OpenID Connect Messenger integration
    this.auth0Domain = null;
    this.auth0GenesysClientId = null;

    // AuthProvider & PKCE state
    this.authProviderRegistered = false;
    this.authCode = null;
    this.codeVerifier = null;

    // Messenger state
    this.messengerInitialized = false;
    this.messengerPluginReady = false;
    this.authCompleted = false;

    // Concurrency guard
    this.authStateChangeInProgress = false;
  }

  _getEnv(key) {
    return (window.__ENV && window.__ENV[key]) ? window.__ENV[key] : null;
  }

  // ===== Load Genesys deployment config =====
  async loadConfig() {
    const res = await fetch('genesys-config.json', { cache: 'no-cache' });
    this.config = await res.json();

    // Read Auth0 env values
    this.auth0Domain = this.auth0Domain || this._getEnv('VITE_AUTH0_DOMAIN');
    this.auth0GenesysClientId = this.auth0GenesysClientId || this._getEnv('VITE_AUTH0_CLIENT_ID');

    if (!this.auth0Domain || !this.auth0GenesysClientId) {
      console.warn('[Genesys] Missing Auth0 domain/client_id. Set window.__ENV.VITE_AUTH0_DOMAIN and VITE_AUTH0_CLIENT_ID.');
    }

    if (this.config?.debug) {
      console.log('Genesys configuration loaded:', this.config);
    }
    return this.config;
  }

  // ===== Bootstrap Genesys SDK =====
  async initializeSDK() {
    if (!this.config) throw new Error('Configuration not loaded.');

    const bootstrapUrl = `https://apps.${this.config.domain}/genesys-bootstrap/genesys.min.js`;
    await new Promise((resolve, reject) => {
      if (window.Genesys && window.Genesys._genesysJs) return resolve();
      (function (g, e, n, es, ys) {
        g['_genesysJs'] = e;
        g[e] = g[e] || function () { (g[e].q = g[e].q || []).push(arguments); };
        g[e].t = 1 * new Date();
        g[e].c = es;
        ys = document.createElement('script');
        ys.async = 1; ys.src = n; ys.charset = 'utf-8';
        ys.onload = resolve;
        ys.onerror = () => reject(new Error('Failed to load Genesys SDK'));
        document.head.appendChild(ys);
      })(window, 'Genesys', bootstrapUrl, {
        environment: this.config.environment,
        deploymentId: this.config.deploymentId,
        debug: this.config.debug
      });
    });

    this.genesysReady = true;
    if (this.config?.debug) console.log('Genesys SDK loaded successfully');
  }

  async waitForGenesysReady() {
    if (this.genesysReady) return;
    await new Promise((resolve) => {
      const int = setInterval(() => {
        if (window.Genesys && window.Genesys._genesysJs) {
          clearInterval(int);
          resolve();
        }
      }, 100);
      setTimeout(() => { clearInterval(int); resolve(); }, 10000);
    });
    this.genesysReady = true;
  }

  setAuth0Client(client) { this.auth0Client = client; }

  // ===== PKCE helpers =====
  _base64url(bytes) {
    let str = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      str += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  async _generatePkcePair() {
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const codeVerifier = this._base64url(verifierBytes);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = this._base64url(new Uint8Array(digest));
    return { codeVerifier, codeChallenge };
  }

  // ===== Second login for Genesys (Auth0 /authorize) =====
  async initiateGenesysAuth() {
    if (!this.auth0Domain || !this.auth0GenesysClientId) {
      console.error('[Genesys] Auth0 domain/client_id not available.');
      return;
    }

    // Optional: gate on primary SPA auth
    if (this.auth0Client) {
      const isAuthenticated = await this.auth0Client.isAuthenticated();
      if (!isAuthenticated) {
        console.log('[Genesys] SPA not authenticated; waiting.');
        return;
      }
    }

    console.log('[Genesys] Initiating Auth0 second authorization for Genesys...');
    sessionStorage.setItem('genesys_auth_pending', 'true');

    const { codeVerifier, codeChallenge } = await this._generatePkcePair();
    sessionStorage.setItem('gc_pkce_verifier', codeVerifier);

    const redirectUri = window.location.origin + window.location.pathname; // exact callback registered in Auth0
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.auth0GenesysClientId,
      redirect_uri: redirectUri,
      scope: 'openid profile email',
      state: 'genesys',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });

    window.location.href = `https://${this.auth0Domain}/authorize?${params.toString()}`;
  }

  // ===== Handle Auth0 callback for Genesys =====
  async handleGenesysAuthCallback() {
    const qs = new URLSearchParams(window.location.search || '');
    const code = qs.get('code');
    const state = qs.get('state');
    const pending = sessionStorage.getItem('genesys_auth_pending');

    if (code && state === 'genesys' && pending === 'true') {
      console.log('[Genesys] Received auth code from Auth0:', code.substring(0, 20) + '...');
      this.authCode = code;
      this.codeVerifier = sessionStorage.getItem('gc_pkce_verifier') || null;

      sessionStorage.removeItem('genesys_auth_pending');
      window.history.replaceState({}, document.title, window.location.pathname);

      if (this.genesysReady) this.registerAuthProvider();
      return true;
    }
    return false;
  }

  // ===== Register AuthProvider per Genesys contract =====
  registerAuthProvider() {
    if (this.authProviderRegistered) {
      console.log('[Genesys] AuthProvider already registered');
      return;
    }
    if (!window.Genesys) {
      console.warn('[Genesys] SDK not available, cannot register AuthProvider');
      return;
    }
    if (!this.authCode) {
      console.log('[Genesys] No auth code available, skipping AuthProvider registration');
      return;
    }

    console.log('[Genesys] Registering AuthProvider plugin...');
    window.Genesys('registerPlugin', 'AuthProvider', (AuthProvider) => {
      console.log('[Genesys] AuthProvider plugin received');

      // getAuthCode (mandatory) — must return authCode, redirectUri, and codeVerifier when PKCE is used. [2](https://all.docs.genesys.com/index.php?title=ATC/Current/AdminGuide/Messenger_configuration&contextManual=AgentGuide)
      AuthProvider.registerCommand('getAuthCode', (e) => {
        console.log('[Genesys] AuthProvider.getAuthCode called');
        const redirectUri = window.location.origin + window.location.pathname;
        const payload = { authCode: this.authCode, redirectUri };
        if (this.codeVerifier) payload.codeVerifier = this.codeVerifier;
        e.resolve(payload);
        console.log('[Genesys] AuthProvider.getAuthCode resolved');
      });

      // reAuthenticate (mandatory) — may trigger full redirect. [2](https://all.docs.genesys.com/index.php?title=ATC/Current/AdminGuide/Messenger_configuration&contextManual=AgentGuide)
      AuthProvider.registerCommand('reAuthenticate', async (e) => {
        console.log('[Genesys] AuthProvider.reAuthenticate called');
        this.authCode = null;
        this.codeVerifier = null;
        try {
          await this.initiateGenesysAuth();
          e.resolve();
        } catch (error) {
          console.error('[Genesys] Re-authentication failed:', error);
          e.reject(error);
        }
      });

      // Subscribe to auth lifecycle events
      // Reference: https://developer.genesys.cloud/commdigital/digital/webmessaging/authenticate
      Genesys('subscribe', 'Auth.authenticating', ({ data }) => {
        console.log('[Genesys] Auth.authenticating:', data);
      });
      Genesys('subscribe', 'Auth.authenticated', ({ data }) => {
        this.authCompleted = true;
        console.log('[Genesys] Auth.authenticated:', data);
        this._tryOpenMessenger(); // only opens once both ready & authenticated
      });
      Genesys('subscribe', 'Auth.authError', ({ data }) => {
        console.error('[Genesys] Auth.authError:', data);
      });
      Genesys('subscribe', 'Auth.tokenError', ({ data }) => {
        console.error('[Genesys] Auth.tokenError:', data);
      });
      Genesys('subscribe', 'Auth.authProviderError', ({ data }) => {
        console.error('[Genesys] Auth.authProviderError:', data);
      });
      
      // Subscribe to logout event (published across browser tabs/devices)
      // Note: This can also be subscribed via AuthProvider.subscribe if available
      Genesys('subscribe', 'Auth.loggedOut', () => {
        console.log('[Genesys] Auth.loggedOut: Clearing auth state');
        this.authCode = null;
        this.codeVerifier = null;
        sessionStorage.removeItem('gc_pkce_verifier');
        this.authCompleted = false;
      });

      // Messenger readiness
      Genesys('subscribe', 'Messenger.ready', () => {
        this.messengerPluginReady = true;
        console.log('[Genesys] Messenger.ready');
        this._tryOpenMessenger();
      });

      console.log('[Genesys] Calling AuthProvider.ready()');
      AuthProvider.ready();
      console.log('[Genesys] AuthProvider registered successfully');
    });

    this.authProviderRegistered = true;
  }

  // ===== Open Messenger only when safe =====
  _tryOpenMessenger() {
    if (this.messengerInitialized) return;
    if (!this.messengerPluginReady) return;
    if (this.config?.authenticatedChat && !this.authCompleted) return;

    console.log('[Genesys] Opening Messenger...');
    Genesys('command', 'Messenger.open', {},
      () => {
        this.messengerInitialized = true;
        if (this.config?.debug) console.log('[Genesys] Messenger opened');
      },
      (err) => {
        console.error('[Genesys] Messenger.open rejected:', err);
      }
    );
  }

  // ===== Initialize messenger (auth-aware) =====
  async initializeMessenger() {
    await this.waitForGenesysReady();
    if (!window.Genesys) throw new Error('Genesys SDK not available');

    // In authenticated mode, do not open here; opening is fully event-gated in _tryOpenMessenger.
    if (!this.config.authenticatedChat) {
      Genesys('subscribe', 'Messenger.ready', () => this._tryOpenMessenger());
    }
  }

  // ===== Called by app.js after primary Auth0 login (optional) =====
  async handleAuthStateChange() {
    if (this.authStateChangeInProgress) {
      console.log('[Genesys] handleAuthStateChange already in progress, skipping');
      return;
    }

    // If callback params are present, let this take precedence
    const handledGenesysCallback = await this.handleGenesysAuthCallback();
    if (handledGenesysCallback) {
      setTimeout(() => this.initializeMessenger(), 300);
      return;
    }

    this.authStateChangeInProgress = true;
    console.log('[Genesys] handleAuthStateChange called');

    try {
      // We need config to decide if authenticated chat is on
      if (!this.config || !this.config.authenticatedChat) {
        console.log('[Genesys] Authenticated chat disabled, skipping');
        return;
      }

      // Grab Auth0 client (SPA) if present
      if (!this.auth0Client && window.auth0Client) {
        console.log('[Genesys] Auth0 client found on window');
        this.setAuth0Client(window.auth0Client);
      }

      let isAuthenticated = true; // allow second login to prompt if SPA client missing
      if (this.auth0Client) {
        isAuthenticated = await this.auth0Client.isAuthenticated();
        console.log('[Genesys] Auth0 authentication status:', isAuthenticated);
      }

      if (isAuthenticated) {
        if (!this.authCode) {
          console.log('[Genesys] Initiating Genesys authentication...');
          await this.initiateGenesysAuth();
        } else {
          console.log('[Genesys] Auth code already available, registering AuthProvider');
          await this.waitForGenesysReady();
          this.registerAuthProvider();
          setTimeout(() => this.initializeMessenger(), 300);
        }
      }
    } catch (error) {
      console.error('[Genesys] Error handling auth state change:', error);
    } finally {
      setTimeout(() => { this.authStateChangeInProgress = false; }, 1000);
    }
  }

  // ===== Main init =====
  async init() {
    try {
      console.log('[Genesys] ===== Initializing Genesys Chat Manager =====');
      await this.loadConfig();
      await this.initializeSDK();

      // Let app.js create the SPA Auth0 client if needed
      await new Promise((resolve) => setTimeout(resolve, 300));
      if (window.auth0Client) {
        console.log('[Genesys] Auth0 client found on window');
        this.setAuth0Client(window.auth0Client);
      } else {
        console.log('[Genesys] Auth0 client not yet available on window');
      }

      // Handle second-login callback (if present)
      const handledCallback = await this.handleGenesysAuthCallback();

      if (this.config.authenticatedChat) {
        if (this.authCode || handledCallback) {
          console.log('[Genesys] Found auth code, registering AuthProvider');
          await this.waitForGenesysReady();
          this.registerAuthProvider();
          setTimeout(() => this.initializeMessenger(), 300);
        } else {
          console.log('[Genesys] Authenticated chat enabled but no auth code yet; waiting for primary Auth0 login or initiating second login.');
        }
      } else {
        console.log('[Genesys] Initializing non-authenticated messenger');
        await this.initializeMessenger();
      }

      console.log('[Genesys] ===== Initialization complete =====');
    } catch (error) {
      console.error('[Genesys] Initialization error:', error);
    }
  }
}

// Create global instance and init
const genesysChatManager = new GenesysChatManager();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => genesysChatManager.init());
} else {
  genesysChatManager.init();
}

// Export for external usage
window.genesysChatManager = genesysChatManager;
