let auth0Client = null;
let authenticatedChat = false;

const fetchAuth0Config = () => fetch("/auth_config.json");

const configureAuth0Client = async () => {
    const response = await fetchAuth0Config();
    const config = await response.json();
  
    auth0Client = await auth0.createAuth0Client({
      name: window.title,
      env: {
        url: window.location.origin
      },
      domain: config.domain,
      clientId: config.clientId,
      useRefreshTokens: false,
      cacheLocation: 'localstorage'
    });
};

const login = async () => {
  await auth0Client.loginWithRedirect({
    authorizationParams: {
      scope: "openid profile email offline_access",
      max_age: 3600,
      redirect_uri: window.location.origin
    }
  });
};

const logout = async () => {

  // Logout of Genesys first
  console.log("Initiating Genesys logout...")
  Genesys("command", "Auth.logout", {}, async (response) => {

    console.log("Initiating Auth0 logout...")
    await auth0Client.logout({
      logoutParams: {
        returnTo: window.location.origin
      }
    }).catch(function(e) {
        console.log("auth0Client logout failed: " + JSON.stringify(e))
    });
  }, (error) => {
    console.log("Genesys Auth.logout rejected: " + JSON.stringify(error))
  });
};

const updateUI = async () => {
  const isAuthenticated = await auth0Client.isAuthenticated();

  document.getElementById("btn-logout").disabled = !isAuthenticated;
  document.getElementById("btn-login").disabled = isAuthenticated;

  if (isAuthenticated) {
      document.getElementById("gated-content").classList.remove("hidden");
  
      document.getElementById(
        "ipt-access-token"
      ).innerHTML = await auth0Client.getTokenSilently();
  
      document.getElementById("ipt-user-profile").textContent = JSON.stringify(
        await auth0Client.getUser()
      );
  
    } else {
      document.getElementById("gated-content").classList.add("hidden");
    }
};

const fetchGenesysConfig = () => fetch("/genesys_config.json");

const initGenesysChat = async () => {
    const response = await fetchGenesysConfig();
    const config = await response.json();	
	
	authenticatedChat = config.authenticatedChat;	
	
	(function (g, e, n, es, ys) {
	  g['_genesysJs'] = e;
	  g[e] = g[e] || function () {
		(g[e].q = g[e].q || []).push(arguments)
	  };
	  g[e].t = 1 * new Date();
	  g[e].c = es;
	  ys = document.createElement('script'); ys.async = 1; ys.src = n; ys.charset = 'utf-8'; document.head.appendChild(ys);
	})(window, 'Genesys', 'https://apps.' + config.domain + '/genesys-bootstrap/genesys.min.js', {
	  environment: config.environment,
	  deploymentId: config.deploymentId,
	  debug: config.debug
	});

	console.log("Subscribing for Journey events")
	Genesys("subscribe", "Journey.ready", function() {
		console.log("Received Journey.ready")

		console.log("Creating trackIdleEvents events")
		Genesys("command", "Journey.trackIdleEvents", {
			idleEvents: [
				{ idleAfterSeconds: 30, eventName: "idle_30_seconds" },
				{ idleAfterSeconds: 60, eventName: "idle_60_seconds" },
				{ idleAfterSeconds: 90, eventName: "idle_90_seconds" },
				{ idleAfterSeconds: 120, eventName: "idle_120_seconds" },
			]
		});

		console.log("Creating trackScrollDepth events")
		Genesys("command", "Journey.trackScrollDepth", {
			scrollDepthEvents: [
				{ percentage: 50, eventName: "scrolled_50_percent" },
				{ percentage: 90, eventName: "bottom_of_page_reached"},
			]
		});

		console.log("Creating trackInViewport events")
		Genesys("command", "Journey.trackInViewport", {
			inViewportEvents: [{ selector: ".testimonial-area", eventName: "testimonial_shown" }]
		});
	});

	Genesys("subscribe", "Journey.qualifiedWebMessagingOffer", ({ data }) => {
		console.log("Received qualified web messaging offer:", data);

		if (data.state == 'qualified') {
			Genesys('command', 'Launcher.show', {}, ()=> console.log("Launcher.show"), (error) => console.log("Couldn't show launcher.", error))
		}
	});

	Genesys("subscribe", "Journey.qualifiedContentOffer", ({ data }) => {
		console.log("Received qualified content offer:", data);
	});

	Genesys("subscribe", "Journey.qualifiedOpenAction", ({ data }) => {
		console.log("Received qualified open action:", data);
	});

	function setParticipantData() {
			console.log("Setting participant data for conversation");
			Genesys("command", "Database.set", {
				messaging: { customAttributes: {
					INDIAL_KEY: 'PPE NTT FNA FNI LiveChat',
					DEALER_CODE: 'DEALER159',
					ADVISOR_NAME: 'Superannuation R Us',
					ADVISOR_CODE: 'SRU001',
					PHONE_NUMBER: '+61290639091'
				}}},
			function(data){ /* fulfilled, returns data */},
			function(){ /* rejected */ });        
		};
	console.log("Subscribing to Database events");
	Genesys("subscribe", "Database.ready", function() {
		console.log("Received Database.ready");

		setParticipantData();
	});

	Genesys("subscribe", "Database.updated", function(e) {
		console.log("Database updated: ", e.data)
	});

	Genesys("subscribe", "Database.removed", function(e) {
		console.log("Database removed: ", e.data)
		
		setParticipantData(); // When a conversation is closed, the database is emptied. So we set the participant data again
	});

	console.log("Subscribing to MessagingService events");
	Genesys("subscribe", "MessagingService.started", ({ data }) => {
		console.log("Received MessagingService started:", data)
	});

	Genesys("subscribe", "MessagingService.restored", ({ data }) => {
		console.log("Received MessagingService restored:", data)
	});

	Genesys("subscribe", "MessagingService.sessionCleared", ({ data }) => {
		console.log("Received MessagingService sessionCleared:", data)
	});

	Genesys("subscribe", "MessagingService.offline", ({ data }) => {
		console.log("Received MessagingService offline:", data)
	});

	Genesys("subscribe", "MessagingService.reconnecting", ({ data }) => {
		console.log("Received MessagingService reconnecting:", data)
	});

	Genesys("subscribe", "MessagingService.reconnected", ({ data }) => {
		console.log("Received MessagingService reconnected:", data)
	});

	Genesys("subscribe", "MessagingService.conversationDisconnected", ({ data }) => {
		console.log("Received MessagingService conversation disconnected:", data)
	});

	Genesys("subscribe", "MessagingService.conversationReset", ({ data }) => {
		console.log("Received MessagingService conversation reset:", data)
	});

	Genesys("subscribe", "MessagingService.conversationCleared", ({ data }) => {
		console.log("Received MessagingService conversation cleared:", data)
	});
	Genesys("subscribe", "MessagingService.error", ({ data }) => {
		console.log("Received MessagingService error:", data)
	});
}

const registerAuthProvider = () => {
  Genesys('registerPlugin', 'AuthProvider', (AuthProvider) => {
    console.log("Registering Genesys AuthProvider plugin")

    // COMMAND
    // *********
    // getAuthCode
    // reAuthenticate

    /* Register Command - mandatory */      
    AuthProvider.registerCommand('getAuthCode', async function(e) {
      // Add the necessary logic and resolve with the authCode and redirectUri provided by your Authentication provider. Messenger will call this command to get the the tokens.
      
      // The values from genesys_auth_provider_state which is updated during the oAuth code flow
      let genesys_auth_provider_state = JSON.parse(sessionStorage.getItem("genesys_auth_provider_state"));
      let auth_code = (genesys_auth_provider_state || {}).auth_code;
      let redirect_uri = (genesys_auth_provider_state || {}).redirect_uri;
      let code_verifier = (genesys_auth_provider_state || {}).code_verifier;
      let nonce = (genesys_auth_provider_state || {}).nonce;

      console.log("AuthProvider.getAuthCode: auth_code is: " + auth_code + ", redirect_uri is: " + redirect_uri + ", code_verifier: " + code_verifier + ", nonce: " + nonce);

      e.resolve({
          authCode: auth_code,          // pass your authorization code here
          redirectUri: redirect_uri,    // pass the redirection URI configured in your Authentication provider here
          codeVerifier: code_verifier,
          nonce: nonce,
        });
    });

    AuthProvider.registerCommand('reAuthenticate', async function(e) {          
      // Messenger will call this command when current refreshToken and/or authCode are no more valid. Brand can add logic here to simply re-login and resolve this command after successful login so that Messenger can get the new authCode. (In case when browser needs to reload for a login, there is no need to resolve this command). Note: After a successful re-login, calling the getAuthCode command is taken care internally and there is no need to call it explicitly again
      // Send authorization request
      console.log("AuthProvider.reAuthenticate: Initiating login() request")
      
      login()
      e.resolve();
    });

    AuthProvider.subscribe('Auth.loggedOut', () => {
      // This event is published across the browser tabs/devices where the user is logged in, so you can do something on logout.
      // For example, clear any authenticated flags that you might have set during login.
      console.log("AuthProvider received Auth.loggedOut: Removing genesys_auth_provider_state from session storage")
      sessionStorage.removeItem("genesys_auth_provider_state");
    });
      
    // Tell Messenger that your plugin is ready (mandatory)
    AuthProvider.ready();
  });

  // Take this opportunity to subscribe to Auth events
  console.log("Subscribing to Auth events");
  Genesys("subscribe", "Auth.authenticating", ({ data }) => {
      console.log("Received Auth.authenticating:", data)
  }); 

  Genesys("subscribe", "Auth.authenticated", ({ data }) => {
      console.log("Received Auth.authenticated:", data)
  }); 

  Genesys("subscribe", "Auth.tokenError", ({ data }) => {
    console.log("Received Auth.tokenError:", data)
  });

  Genesys("subscribe", "Auth.authProviderError", ({ data }) => {
    console.log("Received Auth.authProviderError:", data)
  });

  Genesys("subscribe", "Auth.error", ({ data }) => {
      console.log("Received Auth.error:", data)
  });

  Genesys("subscribe", "Auth.authError", ({ data }) => {
    console.log("Received Auth.authError:", data)
});

  Genesys("subscribe", "Auth.logoutError", ({ data }) => {
    console.log("Received Auth.logoutError:", data)
  });
};

window.onload = async () => {

  // Initialise the Auth0 clientId and Genesys Chat
  await configureAuth0Client()
  await initGenesysChat()

  // Handle authentication re-directs
  const query = window.location.search
  const params = new URLSearchParams(query);
  
  if (params.has("code") && params.has("state")) {

    // Process the login state
    if (!window.location.hash) {

      console.log("ready: handleRedirectCallback() to complete login");
      await auth0Client.handleRedirectCallback();

      // Successful login.
	  if (authenticatedChat) {
		  // Send second authorization request to register the Genesys AuthProvider
		  console.log("ready: sending second auth request for Genesys AuthProvider");
		  await auth0Client.loginWithRedirect({
			authorizationParams: {
			  scope: "openid profile email",
			  max_age: 3600,
			  redirect_uri: window.location.href + "#genesys_login",
			  prompt: "none"
			}
		  });
      }

    } else if (window.location.hash == "#genesys_login") {
	  
      // Because we are using a SPA client in a static website we don't have a JS context in which to create a closure to hold these values securely between page loads
      // Hence for this example we store the auth_code in session storage to make available to all application pages
      let genesys_auth_provider_state = {}
      genesys_auth_provider_state.auth_code = params.get("code");
      genesys_auth_provider_state.state = params.get("state");
      // genesys_auth_provider_state.redirect_uri = window.location.origin;
      genesys_auth_provider_state.redirect_uri = window.location.href;

      auth0_storage = JSON.parse(sessionStorage.getItem(auth0Client.transactionManager.storageKey))
      genesys_auth_provider_state.code_verifier = (auth0_storage || {}).code_verifier;
      genesys_auth_provider_state.nonce = (auth0_storage || {}).nonce;
      
      console.log("onload: genesys_auth_provider state is", genesys_auth_provider_state);
      sessionStorage.setItem("genesys_auth_provider_state", JSON.stringify(genesys_auth_provider_state));
	}

    // Use replaceState to redirect the user away and remove the querystring parameters
    window.history.replaceState({}, document.title, "/");
  }

  // If the Genesys authentication is completed then register our AuthProvider
  if (sessionStorage.getItem("genesys_auth_provider_state")) {
    registerAuthProvider();
  }

  updateUI();
};