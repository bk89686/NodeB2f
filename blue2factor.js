/**
 *  Copyright Blue2Factor 2022
 */
 
 "use strict";

const url = require('url');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');


const secureUrl = "https://secure.blue2factor.com";
const SUCCESS = 0;
const FAILURE = 1;
const EXPIRED = -1;
var b2fCookie = null;
var redirect = null;
var authenticated = false;

const app = express();
app.use(cookieParser());
	
function isAuthenticated() {
	return authenticated;
}
	
function getRedirect(response) {
	console.log("getting redirect '" + redirect + "'");
	if (redirect != null) {
		return response.redirect(redirect);
	}
}

function setB2fCookie(res) {
	if (b2fCookie != null) {
		res.cookie("B2F_AUTHN", b2fCookie);
	}
	return res
}

function getEndpoint(companyId) {
    return secureUrl + "/SAML2/SSO/" + companyId + "/Token";
}

function getFailureUrl(companyId) {
    return secureUrl + "/failure/" + companyId + "/recheck";
}

function getResetUrl(companyId) {
    return secureUrl + "/failure/" + companyId + "/reset";
}

function getIssuer(companyId) {
    return secureUrl + "/SAML2/SSO/" + companyId + "/EntityId";
}

function getSignout(companyId, response){
    return response.redirect(secureUrl + "/SAML2/SSO/" + companyId + "/Signout");
}

async function authenticateRequestExpress(request, companyId, loginUrl, privateKeyStr) {
	const b2fAuth = getB2fAuthCookieOrPost(request);
	const b2fSetup = getSetupFromPost(request);
	const myUrl = getUrl(request);
	const resp = await authenticate(myUrl, b2fAuth, companyId, loginUrl, b2fSetup, privateKeyStr);
	console.info("success " + resp.success);
	b2fCookie = resp.b2fSetup;
	redirect = resp.redirect;
	return resp.success;
}

function getUrl(req) {
    return url.format({
        protocol: req.protocol,
        host: req.get('host'),
        pathname: req.originalUrl
    });
}

function getSetupFromPost(request) {
	var setup = null;
	if (request.body != null) {
		setup = req.body.b2fSetup;	
	}
	return setup;
}

function getB2fAuthCookieOrPost(request) {
	var authn = null;
	if (request.body != null) {
		authn = req.body.B2F_AUTHN;
	}
	if (authn == null) {
		authn = getCookie(request);
	}
	return authn;
}

var b2fPrivateKey = ``;

var testCompanyId = "";
var testUrl = "https://www.blue2factor.com/mytest";
var testJwt = "";
async function test(){
	const resp = await authenticate(testUrl, testJwt, testCompanyId, testUrl, "", b2fPrivateKey);
	console.info("success " + resp.success);
	return resp.success;
}

async function authenticate(url, jwt, companyId, loginUrl, setup, privateKeyStr) {
	var success = false;
	var token = null;
	var redirect = null;
	var b2fSetup = setup;
	if (jwt) {
		console.log("jwt found");
		var successAndToken = await b2fAuthorized(jwt, companyId, loginUrl, privateKeyStr);
		if (successAndToken.success) {
			success = true;
			token = successAndToken.token;
		} else {
			var urlSplit = url.split("?")[0];
			redirect = getFailureUrl(companyId) + "?url=" + encodeURIComponent(urlSplit);
			console.log("redirect to: " + redirect);
		}
	} else {
		console.log("no jwt");
		var urlSplit = url.split("?")[0];
		redirect = getResetUrl(companyId) + "?url=" + encodeURIComponent(urlSplit);
		console.log("redirect to: " + redirect);
	}
	
	return {success, token, redirect, b2fSetup};
}


async function b2fAuthorized(jwt, companyId, loginUrl, privateKeyStr) {
	var token = "";
	var success = false;
	try {
		var validInt = await tokenIsValid(jwt, companyId, loginUrl);
		if (validInt == SUCCESS) {
			token = jwt;
			success = true
		} else {
			if (validInt == EXPIRED) {
				console.log("Jwt was expired. Will attempt to get a new one");
				var resp = await getNewToken(jwt, companyId, loginUrl, privateKeyStr);
				if (resp.success) {
					success = true;
					token = resp.token;
				}
			}
		}
	} catch (e) {
		console.error(e);
	}
	return {success, token};
}

async function getNewToken(jwt, companyId, loginUrl, privateKeyStr) {
	var success = false;
	var token = "";
	try {
		
		const signature = getJwtSignature(jwt, privateKeyStr);
		const tokenUrl = getEndpoint(companyId);
		console.log("getNewToken from " + tokenUrl);
		const res = await axios.get(tokenUrl, {
			headers: {
				Authorization: 'Bearer ' + jwt + "&" + signature
			}
		});
		if (res) {
			console.log("response status:" + res.status);
			if (res.status == 200) {
				const outcome = res.data.outcome;
				console.log("response output:" + res.data.outcome);
				if (outcome == SUCCESS) {
					token = res.data.token;
					outcome = await tokenIsValid(newJwt, companyId, loginUrl);
				} else {
					console.log("failed: " + res.data.reason);
				}
			} else {
				console.log("bad response:" + res.status);
			}
		} else {
			console.log("null response");
		}
	} catch (err) {
		console.error(err);
	}
	return {success, token};
}

function getJwtSignature(jwtStr, privateKeyStr) {
	const pemPrefix = '-----BEGIN RSA PRIVATE KEY-----';
    const pemSuffix = '-----END RSA PRIVATE KEY-----';
    const regex = new RegExp('[\n\r]', 'g');
    var privateKeyStrFormatted = privateKeyStr.replace(pemPrefix, '').replace(pemSuffix, '');
    privateKeyStrFormatted = privateKeyStrFormatted.replace(regex, '');
    privateKeyStrFormatted = addNewLinesToKeyString(privateKeyStrFormatted);
    privateKeyStrFormatted = pemPrefix + "\n" + privateKeyStrFormatted + pemSuffix;
    console.log("jwt: '" + jwtStr + "'");
    console.log("pk: " + privateKeyStrFormatted);
    const signature = crypto.sign("sha256", Buffer.from(jwtStr), privateKeyStrFormatted); 
    /*{
		key: privateKey,
		padding: crypto.constants.RSASSA-PKCS1-v1_5
	});*/
	const encoded = signature.toString('base64');
	return encoded;
}

async function tokenIsValid(authToken, companyId, loginUrl) {
	var outcome = FAILURE;
	const url = getX5u(authToken);
	if (url) {
		const publicKey = await getPublicKeyFromUrl(url);
		console.info("publicKey: " + publicKey);
		try {
			const options = {
				algorithms: ["RS256"],
				audience: loginUrl,
				issuer: getIssuer(companyId)
			}
			jwt.verify(authToken, publicKey, options);
			outcome = SUCCESS;
		} catch (error) {
			if (error.name == "TokenExpiredError") {
				console.log("token was expired");	
				outcome = EXPIRED;
			} else {
				console.log("token validation error: " + error.name);
			}
		}
	}
	return outcome;
}

function getX5u(authToken) {
	var x5u = null;
	try {
		const header = authToken.split(".")[0];
		let bufferObj = Buffer.from(header, "base64");
		const headerDecoded = bufferObj.toString("utf8");
		const headerJson = JSON.parse(headerDecoded);
		x5u = headerJson.x5u;
	} catch (error) {
		console.error(error);
	}
	return x5u;
}

async function getPublicKeyFromUrl(url) {
	var pk = null; 
	console.log("will check " + url);
	const res = await axios.get(url);
	if (res && res.status == 200) {
		pk = res.data;
		pk = "-----BEGIN PUBLIC KEY-----\n" + addNewLinesToKeyString(res.data) + 
                   "-----END PUBLIC KEY-----";
	}
	console.log("pk for url: " + pk);
	return pk;
}

function addNewLinesToKeyString(keyStr) {
	var nextLine;
	var newKey = "";
	var i = 0;
	for (i=0; i*64<=keyStr.length; i+=1) {
		nextLine = keyStr.substring(i*64, (i+1)*64);
		newKey = newKey + nextLine + "\n"; 
	}
	//remove last \n ?
	return newKey;
}

function getCookie(req) {
	var cookie = null;
	try {
		cookie = req.cookies["B2F_AUTHN"];
	} catch (e) {
		console.log("cookie not found");
	}
	return cookie??null;
}

module.exports = { test, setB2fCookie, getRedirect, authenticateRequestExpress };

