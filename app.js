import { createAuth0Client } from '@auth0/auth0-spa-js';

// app.js (Vite module)
window.__ENV = {
  VITE_AUTH0_DOMAIN: import.meta.env.VITE_AUTH0_DOMAIN,
  VITE_AUTH0_CLIENT_ID: import.meta.env.VITE_AUTH0_CLIENT_ID
};

// DOM elements
const loading = document.getElementById('loading');
const error = document.getElementById('error');
const errorDetails = document.getElementById('error-details');
const app = document.getElementById('app');
const loggedOutSection = document.getElementById('logged-out');
const loggedInSection = document.getElementById('logged-in');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const profileContainer = document.getElementById('profile');

let auth0Client;

// Clear any stale Auth0 state (useful for debugging)
function clearAuth0State() {
  try {
    // Clear Auth0 transaction state from localStorage
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
      if (key.includes('auth0') || key.includes('@@auth0spajs')) {
        console.log('Clearing Auth0 key:', key);
        localStorage.removeItem(key);
      }
    });
    console.log('Auth0 state cleared');
  } catch (err) {
    console.warn('Error clearing Auth0 state:', err);
  }
}

// Initialize Auth0 client
async function initAuth0() {
  try {
    const domain = import.meta.env.VITE_AUTH0_DOMAIN;
    const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID;
    const redirectUri = window.location.origin;

    console.log('Initializing Auth0 with:', {
      domain,
      clientId,
      redirectUri,
      currentUrl: window.location.href
    });

    if (!domain || !clientId) {
      throw new Error('Missing Auth0 configuration. Please check your .env file.');
    }

    auth0Client = await createAuth0Client({
      domain: domain,
      clientId: clientId,
      authorizationParams: {
        redirect_uri: redirectUri,
        scope: 'openid profile email' // Request required scopes
      },
      cacheLocation: 'localstorage', // Use localStorage to persist transaction state
      useRefreshTokens: false
    });

    // Expose Auth0 client to window for Genesys chat integration
    window.auth0Client = auth0Client;

    console.log('Auth0 client created successfully');

    // Check if user is returning from login - handle this BEFORE checking auth status
    const urlParams = new URLSearchParams(window.location.search);
    const hashParams = window.location.hash ? new URLSearchParams(window.location.hash.substring(1)) : new URLSearchParams();
    const hasCode = urlParams.has('code') || hashParams.has('code');
    const hasState = urlParams.has('state') || hashParams.has('state');
    const hasError = urlParams.has('error') || hashParams.has('error');
    const isGenesysAuthPending = sessionStorage.getItem('genesys_auth_pending') === 'true';

    // Skip handling if this is the Genesys auth callback (handled by genesys-chat.js)
    // We detect this by checking if we're already authenticated and there's a code
    if (isGenesysAuthPending && hasCode) {
      console.log('Detected Genesys auth callback, will be handled by genesys-chat.js');
      // Still update UI but don't process as regular Auth0 callback
      await updateUI();
      return;
    }

    if (hasCode && hasState) {
      console.log('Detected redirect callback, handling...');
      try {
        await handleRedirectCallback();
        // After successful callback, update UI
        await updateUI();
        return; // Exit early after handling callback
      } catch (err) {
        // If callback fails, still try to update UI (might already be authenticated)
        console.warn('Callback handling failed, checking auth status anyway:', err);
      }
    } else if (hasError) {
      // Handle error from Auth0
      const error = urlParams.get('error');
      const errorDescription = urlParams.get('error_description');
      console.error('Auth0 error in URL:', error, errorDescription);
      
      // Provide helpful messages for common errors
      let errorMessage = `Authentication error: ${error}`;
      if (error === 'access_denied') {
        errorMessage = 'Access denied. This may be due to:\n' +
          '1. Missing required scopes in Auth0 application settings\n' +
          '2. User denied consent\n' +
          '3. Application not authorized for this user\n\n' +
          `Details: ${errorDescription || 'No additional details'}`;
      } else if (errorDescription) {
        errorMessage += `. ${errorDescription}`;
      }
      
      showError(errorMessage);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
      await updateUI();
      return;
    }

    // Update UI based on authentication state
    await updateUI();
  } catch (err) {
    console.error('Init Auth0 error:', err);
    showError(`Initialization failed: ${err.message || err.error || 'Unknown error'}`);
  }
}

// Handle redirect callback
async function handleRedirectCallback() {
  try {
    console.log('Handling redirect callback...');
    console.log('Current URL:', window.location.href);
    console.log('Query params:', window.location.search);
    
    // Check if we have the necessary parameters
    const urlParams = new URLSearchParams(window.location.search);
    if (!urlParams.has('code') || !urlParams.has('state')) {
      throw new Error('Missing code or state parameter in callback URL');
    }

    const result = await auth0Client.handleRedirectCallback();
    console.log('Redirect callback result:', result);
    
    // Clean up the URL to remove query parameters
    window.history.replaceState({}, document.title, window.location.pathname);
    console.log('URL cleaned, redirect handled successfully');
  } catch (err) {
    console.error('Redirect callback error:', err);
    console.error('Error details:', {
      message: err.message,
      error: err.error,
      errorDescription: err.error_description,
      errorCode: err.error_code,
      stack: err.stack
    });
    
    // If it's a missing_transaction error, provide helpful message
    if (err.error === 'missing_transaction' || err.message?.includes('missing_transaction')) {
      const errorMsg = 'Session expired. This usually happens if you refreshed the page during login. Please try logging in again.';
      showError(errorMsg);
      // Clean up URL and allow user to try again
      window.history.replaceState({}, document.title, window.location.pathname);
    } else {
      showError(`Authentication failed: ${err.error || err.message || 'Unknown error'}. ${err.error_description || ''}`);
    }
    throw err; // Re-throw so caller can handle
  }
}

// Update UI based on authentication state
async function updateUI() {
  try {
    const isAuthenticated = await auth0Client.isAuthenticated();
    console.log('Authentication status:', isAuthenticated);
    
    if (isAuthenticated) {
      showLoggedIn();
      await displayProfile();
      
      // Notify Genesys chat manager of authentication state change
      if (window.genesysChatManager) {
        window.genesysChatManager.setAuth0Client(auth0Client);
        await window.genesysChatManager.handleAuthStateChange();
      }
    } else {
      showLoggedOut();
    }
    
    hideLoading();
  } catch (err) {
    console.error('Update UI error:', err);
    showError(`Failed to check authentication: ${err.message || err.error || 'Unknown error'}`);
  }
}

// Display user profile
async function displayProfile() {
  try {
    const user = await auth0Client.getUser();
    const placeholderImage = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='110' height='110' viewBox='0 0 110 110'%3E%3Ccircle cx='55' cy='55' r='55' fill='%2363b3ed'/%3E%3Cpath d='M55 50c8.28 0 15-6.72 15-15s-6.72-15-15-15-15 6.72-15 15 6.72 15 15 15zm0 7.5c-10 0-30 5.02-30 15v3.75c0 2.07 1.68 3.75 3.75 3.75h52.5c2.07 0 3.75-1.68 3.75-3.75V72.5c0-9.98-20-15-30-15z' fill='%23fff'/%3E%3C/svg%3E`;
    
    // Escape single quotes in placeholderImage for use in JavaScript string within HTML attribute
    const escapedPlaceholder = placeholderImage.replace(/'/g, "\\'");
    
    profileContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; gap: 1rem;">
        <img 
          src="${user.picture || placeholderImage}" 
          alt="${user.name || 'User'}" 
          class="profile-picture"
          style="
            width: 110px; 
            height: 110px; 
            border-radius: 50%; 
            object-fit: cover;
            border: 3px solid #63b3ed;
          "
          onerror="this.src='${escapedPlaceholder}'"
        />
        <div style="text-align: center;">
          <div class="profile-name" style="font-size: 2rem; font-weight: 600; color: #f7fafc; margin-bottom: 0.5rem;">
            ${user.name || 'User'}
          </div>
          <div class="profile-email" style="font-size: 1.15rem; color: #a0aec0;">
            ${user.email || 'No email provided'}
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    console.error('Error displaying profile:', err);
  }
}

// Event handlers
async function login() {
  try {
    console.log('Initiating login...');
    // Explicitly request scopes to ensure proper authorization
    await auth0Client.loginWithRedirect({
      authorizationParams: {
        scope: 'openid profile email' // Ensure scopes are requested
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    showError(`Login failed: ${err.message || err.error || 'Unknown error'}`);
  }
}

async function logout() {
  try {
    await auth0Client.logout({
      logoutParams: {
        returnTo: window.location.origin
      }
    });
  } catch (err) {
    showError(err.message);
  }
}

// UI state management
function showLoading() {
  loading.style.display = 'block';
  error.style.display = 'none';
  app.style.display = 'none';
}

function hideLoading() {
  loading.style.display = 'none';
  app.style.display = 'flex';
}

function showError(message) {
  loading.style.display = 'none';
  app.style.display = 'none';
  error.style.display = 'block';
  errorDetails.textContent = message;
  console.error('Error displayed to user:', message);
}

function showLoggedIn() {
  loggedOutSection.style.display = 'none';
  loggedInSection.style.display = 'flex';
}

function showLoggedOut() {
  loggedInSection.style.display = 'none';
  loggedOutSection.style.display = 'flex';
}

// Event listeners
loginBtn.addEventListener('click', login);
logoutBtn.addEventListener('click', logout);

// Initialize the app
initAuth0();