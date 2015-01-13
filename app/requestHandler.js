var path = require("path");
var fs = require("fs");
var uuid = require("uuid");
var crypto = require('crypto');
var async = require('async');
var child_process = require('child_process');
var validator = require("validator");

var PBKDF2_ITERATIONS = 10000;
var PBKDF2_KEYLEN = 256;

function RequestHandler(redis) {
	var self = this;
	this.handle = this.handle.bind(this);

	this._redis = redis;
}

RequestHandler.prototype.handle = function(req, res, next) {
	var url = path.normalize(req.url);

	var method = req.method;

	// treat PUT requests like POST requests
	if(method === 'PUT')
		method = 'POST';

	if(req.method === 'GET') {
		return this.getRessource(req, res);
	}
	else if(method === 'POST' && url === process.config.uriNew && allowed(req, res)) {
		return this.newStorage(res);
	}
	else if(method === 'POST') {
		return this.uploadFile(req, res)
	}
	else if(method === 'DELETE') {
		return this.deleteStorage(req, res);
	}
	else {
		return this.error(new Error("Unexpected request"), res);
	}
	return next();
}

function isValidPublic(public) {
	return (public != null && validator.isUUID(public));
}

function parseRessourcePath(reqPath, res) {
	var normalizedPath = path.normalize(reqPath);

	if(normalizedPath !== reqPath) {
		// given request path contained normalizable parts
		// this can be due to missing path components like
		// public identifier and is therefore generally
		// forbidden
		res.writeHead(400);
		res.end("Invalid url");
	}

	var pathChunks = reqPath.substr(path.sep.length).split(path.sep);
	var public = pathChunks[0];
	var blobname = pathChunks[1];

	if(public == null || !isValidPublic(public)) {
		// invalid request - QSV id missing or invalid
		res.writeHead(400);
		res.end("Storage Volume ID missing or invalid");
	}

	if(blobname === "") {
		blobname = null;
	}

	return [public, blobname];
}

RequestHandler.prototype.getRessource = function(req, res) {
	var self = this;

	async.waterfall([
		// check syntactical correctness of request
		function(callback) {
			var p = parseRessourcePath(req.url, res);
			var public = p[0];
			var blobname = p[1]; // blobname may be null if QSV is probed

			callback(null, public, blobname);
		},
		// check existence of public id
		function(public, blobname, callback) {
			self._redis.exists(public, function(err, public_exists) {
				if(err) {
					return callback(err);
				}
				if(public_exists === 0) {
					// QSV with the given public does not exist
					res.writeHead(404);
					return res.end("Unknown Storage Volume");
				}
				else if(public_exists && blobname === null) {
					// only QSV probing requested
					// nothing more to do
					res.writeHead(200);
					return res.end("Storage Volume exists");
				}
				callback(null, public, blobname);
			});
		},
		// check existence of blob
		function(public, blobname, callback) {
			var blobPath = path.join(process.config.dataDir, public, blobname);
			fs.exists(blobPath, function(exists) {
				if(exists) {
					callback(null, public, blobname);
				}
				else {
					// nothing more to do
					res.writeHead(404);
					return res.end("Unknown blob name");
				}
			});
		},
		// deliver blob
		function(public, blobname, callback) {
			var blobPath = path.join(process.config.dataDir, public, blobname);
			var blobReadStream = fs.createReadStream(blobPath);
			blobReadStream.on('open', function() {
				res.writeHead(200);
				blobReadStream.pipe(res);
				callback(null);
			});
			blobReadStream.on('error', function(err) {
				callback(err);
			});
		}
	], function(err) {
		if(err) {
			self.error(err, res);
		}
	});
}

function allowed(req, res) {
	var i;

	if(process.config.creater_ip_whitelist === null)
		return true;
	var remote = req.connection.remoteAddress;
	if(req.headers['x-real-ip'] !== undefined)
		remote = req.headers['x-real-ip'];
	console.log(remote);

	return process.config.creater_ip_whitelist.indexOf(remote) != -1;
}

RequestHandler.prototype.newStorage = function(res) {
	var self = this;
	var public = uuid.v4();
	
	async.waterfall([
		// Create Randum Bytes
		function(callback) {
			var tokenLength = 128;
			var revokeTokenLength = 128;
			var saltLength = 128;
			var requiredBytes = tokenLength + revokeTokenLength + saltLength;
			crypto.randomBytes(requiredBytes, function(ex, buf) {
				var token = buf.slice(0,tokenLength).toString('base64')
				var revoke_token = buf.slice(tokenLength,tokenLength+revokeTokenLength).toString('base64');
				var salt = buf.slice(tokenLength+revokeTokenLength,requiredBytes).toString('base64');
				callback(null, token, revoke_token, salt);
			});
		},
		// Create filedir
		function(token, revoke_token, salt, callback) {
			child_process.execFile(path.join(process.root,
					process.config.storageCreater), [
						process.config.dataDir,
						public
					], {
						cwd: process.root,
						timeout: 10000
					},
					function(err, stdout, stderr) {
				callback(err, token, revoke_token, salt);
			});
		},
		// Write into Database
		function(token, revoke_token, salt, callback) {
			var transaction = self._redis.multi();
			transaction.hset(public, "salt", salt);
			// hash token
			crypto.pbkdf2(token, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, function(err, derivedKey) {
				transaction.hset(public, "token", derivedKey);
				// hash revoke_token
				crypto.pbkdf2(revoke_token, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, function(err, derivedKey) {
					transaction.hset(public, "revoke_token", derivedKey);
					transaction.bgsave();
					transaction.exec(function(err) {
						callback(err, token, revoke_token);
					});
				});
			});
		},
	], function(err, token, revoke_token) {
		if(err) {
			self.error(err, res);
		}
		// storage volume created
		res.writeHead(201);
		res.end(JSON.stringify({
			public: public,
			revoke_token: revoke_token,
			token: token
		}));
	});
}

RequestHandler.prototype.deleteStorage = function(req, res) {
	var self = this;

	var pathParts = parseRessourcePath(req.url, res);
	var public = pathParts[0];
	var blob = pathParts[1];

	async.waterfall([
		// Authenticate token
		function(callback) {
			var submittedToken = req.headers[process.config.tokenHeader];
			var tokenMissing = submittedToken === undefined;

			if(tokenMissing) {
				// no token has been submitted
				res.writeHead(401);
				return res.end("Revoke token required");
			}

			// Hash submitted token and compare
			self._auth_token(public, "revoke_token", submittedToken, new AuthHandler(
				// unknown entity
				function() {
					// invalid (unused) storage volume id (public)
					res.writeHead(404);
					res.end("Unknown Storage Volume");
				},
				// rejected - token is incorrect
				function() {
					res.writeHead(403);
					res.end("Invalid token");
				},
				// granted - delete
				function() {
					// process deletion while rushing down the waterfall
					callback(null);
				},
				function(err) {
					callback(err);
				}
			));
		},
		// delete from filesystem and from database
		function(callback) {
			if(blob != null) {
				// delete only a single blob inside a storage volume
				async.parallel([
					// remove public's directory from filesystem
					function(callback) {
						child_process.execFile(path.join(process.root,
							process.config.blobDeleter), [
								process.config.dataDir,
								public,
								blob
							], {
								cwd: process.root,
								timeout: 10000
							},
							function(err, stdout, stderr) {
								callback(err);
							}
						);
					},
				], function(err) {
					callback(err);
				});
			}
			else {
				// delete whole storage volume
				async.parallel([
					// remove public's directory from filesystem
					function(callback) {
						child_process.execFile(path.join(process.root,
							process.config.storageRevoker), [
								process.config.dataDir,
								public
							], {
								cwd: process.root,
								timeout: 10000
							},
							function(err, stdout, stderr) {
								callback(err);
							}
						);
					},
					// delete DB entry
					function(callback) {
						self._redis.del(public, function(err) {
							callback(err)
						})
					}
				], function(err) {
					callback(err);
				});
			}
		}
	], function(err) {
		if(err)
			return self.error(err, res);
		// successfully deleted
		res.writeHead(204);
		res.end();
	});
}

function AuthHandler(unknown, rejected, granted, error) {
	this.unknown = unknown;
	this.rejected = rejected;
	this.granted = granted;
	this.error = error;
}

RequestHandler.prototype._auth_token = function(public, tokenType, tokenValue, authHandler) {
	var self = this;

	async.waterfall([
		// get salt and hash from DB
		function(callback) {
			self._redis.hmget(public, tokenType, "salt", function(err, values) {
				if(err) {
					callback(err);
				}
				var storedHash = values[0];
				var salt = values[1];
				if(storedHash == null || salt == null) {
					authHandler.unknown();
				}
				else {
					callback(null, storedHash, salt);
				}
			});
		},
		// hash submitted token and compare to stored hash
		function(storedHash, salt, callback) {
			crypto.pbkdf2(tokenValue, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, function(err, calcHash) {
				var isAuthorized = false;
				if(err) {
					callback(err);
				}
				if(calcHash.toString() === storedHash) {
					isAuthorized = true;
				}
				callback(null, isAuthorized);
			});
		},
		// respond
		function(isAuthorized, callback) {
			if(isAuthorized) {
				authHandler.granted();
			}
			else {
				authHandler.rejected();
			}
			callback(null);
		},
	],
	function(err) {
		if(err) {
			authHandler.error(err);
		}
	});
}

RequestHandler.prototype.uploadFile = function(req, res) {
	var self = this;
	var hasFile = false;

	var p = parseRessourcePath(req.url, res)
	var public = p[0];
	var chunkname = p[1];

	var submittedToken = req.headers[process.config.tokenHeader];
	var tokenMissing = submittedToken == null;
	if(tokenMissing) {
		// no token submitted
		res.writeHead(401);
		return res.end("Token required");
	}

	// Hash submitted token and compare
	this._auth_token(public, "token", submittedToken, new AuthHandler(
		// unknown entity
		function() {
			// invalid (unused) storage volume id (public)
			res.writeHead(404);
			res.end("Unknown Storage Volume");
		},
		// rejected - token is incorrect
		function() {
			res.writeHead(403);
			res.end("Invalid token");
		},
		// granted
		function() {
			var saveTo = path.join(process.config.dataDir, public, chunkname);
			req.pipe(fs.createWriteStream(saveTo));
			req.on('end', function() {
				res.writeHead(200);
				res.end("Upload successful");
			});
		},
		function(err) {
			self.error(err, res);
		}
	));
}

RequestHandler.prototype.error = function(err, res) {
	console.log(err);
	if(res) {
		res.writeHead(500);
		res.end("Internal server error");
	}
}
module.exports = RequestHandler;
