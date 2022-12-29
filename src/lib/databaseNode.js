function initApp(self) {
	const { initializeApp, onLog } = require("firebase/app");
	const { getAuth } = require("firebase/auth");
	const { getDatabase } = require("firebase/database");

	// Get warning message from bad database url configured
	onLog((log) => self.warn(log.message), { level: "warn" });

	self.app = initializeApp({
		apiKey: self.credentials.apiKey,
		databaseURL: self.credentials.url,
	});

	self.auth = getAuth(self.app);
	self.db = getDatabase(self.app);
}

function initAppWithSDK(self) {
	const { cert, initializeApp } = require("firebase-admin/app");
	const { getDatabase } = require("firebase-admin/database");

	try {
		const content = JSON.parse(self.credentials.json || "{}");

		const isContentNotValid = isJSONContentValid(content);

		if (isContentNotValid) throw new Error(isContentNotValid);

		self.app = initializeApp({
			credential: cert(content),
			databaseURL: self.credentials.url,
		});

		self.db = getDatabase(self.app);
	} catch (error) {
		throw Error(error);
	}
}

function initConnectionStatus(self) {
	const { ref, onValue } = require("firebase/database");

	if (!self.db) return;

	onValue(
		ref(self.db, ".info/connected"),
		(snapshot) => {
			if (snapshot.val() === true) {
				setNodesConnected(self);
				self.log(`Connected to Firebase database: ${self.app.options?.databaseURL}`);
			} else {
				setNodesConnecting(self);
				self.log(`Connecting to Firebase database: ${self.app.options?.databaseURL}`);
			}
		},
		(error) => self.error(error)
	);
}

function isJSONContentValid(content) {
	if (Object.keys(content).length === 0) {
		return "JSON Content must contain 'projectId', 'clientEmail' and 'privateKey'";
	} else if (!content["project_id"]) {
		return "JSON Content must contain 'projectId'";
	} else if (!content["client_email"]) {
		return "JSON Content must contain 'clientEmail'";
	} else if (!content["private_key"]) {
		return "JSON Content must contain 'privateKey'";
	}

	return;
}

// TODO: Add other authentication methods
async function logIn(self) {
	switch (self.config.authType) {
		case "anonymous":
			await logInAnonymously(self);
			break;
		case "email":
			await logInWithEmail(self);
			break;
		case "privateKey":
			logInWithPrivateKey(self);
			break;
		case "JSONWebToken":
			await logInWithToken(self);
			break;
		case "customToken":
			await logInWithCustomToken(self);
			break;
	}
}

async function logInAnonymously(self) {
	const { signInAnonymously } = require("firebase/auth");

	initApp(self);
	await signInAnonymously(self.auth);
}

// Should work but this SHITTTTT don't!
async function logInWithCustomToken(self) {
	const { signInWithCustomToken } = require("firebase/auth");
	const { getAuth } = require("firebase-admin/auth");

	initAppWithSDK(self);

	const claims = {
		admin: self.config.admin || false,
		debug: self.config.debug || false,
		...(self.config.jwtClaims || {}),
	};

	const notAllowed = [
		"alg",
		"acr",
		"amr",
		"at_hash",
		"aud",
		"auth_time",
		"azp,cnf",
		"c_hash,exp",
		"firebase,iat",
		"iss",
		"jti",
		"nbf",
		"nonce",
		"sub",
	];

	if (Object.keys(claims).some((key) => notAllowed.includes(key))) throw new Error("Oh Sh*t...");

	const token = await getAuth(self.app).createCustomToken(self.credentials.uid, claims);

	await signInWithCustomToken(self.app, token);
}

async function logInWithEmail(self) {
	const {
		createUserWithEmailAndPassword,
		fetchSignInMethodsForEmail,
		signInWithEmailAndPassword,
	} = require("firebase/auth");

	initApp(self);

	// Checks if the user already has an account otherwise it creates one
	const method = await fetchSignInMethodsForEmail(self.auth, self.credentials.email);

	if (method.length === 0 && self.config.createUser) {
		await createUserWithEmailAndPassword(self.auth, self.credentials.email, self.credentials.password);

		self.warn(
			`The user "${self.credentials.email}" has been successfully created. You can delete it in the Authenticate section if it is an error.`
		);
	} else if (method.includes("password")) {
		await signInWithEmailAndPassword(self.auth, self.credentials.email, self.credentials.password);
		// TODO: to see... else if (method.includes("link")) {}
	} else {
		throw new Error("auth/email-not-valid");
	}
}

function logInWithPrivateKey(self) {
	initAppWithSDK(self);
}

async function logInWithToken(self) {
	const { signInWithCustomToken } = require("firebase/auth");

	initApp(self);
	await signInWithCustomToken(self.auth, self.credentials.token);
}

async function logOut(self) {
	const { deleteApp } = require("firebase/app");
	const firebaseAdmin = require("firebase-admin/app");

	if (!self.app) return;

	await signOut(self);

	if (self.config.authType === "privateKey") {
		await firebaseAdmin.deleteApp(self.app);
	} else {
		await deleteApp(self.app);
	}
}

function parseErrorMsg(msg) {
	if (msg.includes("auth/internal-error")) return "Please check your email address and password";
	if (msg.includes("auth/api-key-not-valid")) return "Please check your API key";
	if (msg.includes("auth/email-not-valid")) return "Please check your email address or select 'create a new user'";
	return msg;
}

function setNodesConnected(self) {
	self.connected = true;
	for (const node of self.nodes) {
		node.status({ fill: "green", shape: "dot", text: "connected" });
	}
}

function setNodesConnecting(self) {
	self.connected = false;
	for (const node of self.nodes) {
		node.status({ fill: "yellow", shape: "ring", text: "connecting" });
	}
}

function setNodesDisconnected(self) {
	self.connected = false;
	for (const node of self.nodes) {
		node.status({ fill: "red", shape: "dot", text: "disconnected" });
	}
}

async function signOut(self) {
	const { signOut } = require("firebase/auth");

	if (!self.auth) return;
	if (self.config.authType === "privateKey") return;

	await signOut(self.auth);
}

module.exports = { initConnectionStatus, logIn, logOut, parseErrorMsg, setNodesDisconnected };
