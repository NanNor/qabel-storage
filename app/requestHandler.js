var path = require("path");
var fs = require("fs");
var uuid = require("uuid");
var crypto = require('crypto');
var async = require('async');
var child_process = require('child_process');

function RequestHandler(redis) {
	var self = this;
	this.handle = this.handle.bind(this);

	this._redis = redis;
}

RequestHandler.prototype.handle = function(req, res, next) {
	if(req.method === 'GET')
		return next();

	var url = path.normalize(req.url);

	var method = req.method;
	if(method == 'PUT')
		method = 'POST';
	if(url === process.config.uriNew && method == 'POST' && allowed(req, res)) {
		return this.newStorage(res);
	}
	else if(method === 'DELETE') {
		return this.deleteStorage(req, res);
	}
	else {
		return this.uploadFile(req, res)
	}
	return next();
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
			crypto.randomBytes(256, function(ex, buf) {
				var token = buf.slice(0,128).toString('base64')
				var revoke_token = buf.slice(128,256).toString('base64');
				callback(null, token, revoke_token);
			});
		},
		// Create filedir
		function(token, revoke_token, callback) {
			child_process.execFile(path.join(process.root,
					process.config.storageCreater), [
						process.config.dataDir,
						public
					], {
						cwd: process.root,
						timeout: 10000
					},
					function(err, stdout, stderr) {
				callback(err, token, revoke_token);
			});
		},
		// Write into Database
		function(token, revoke_token, callback) {
			var transaction = self._redis.multi()
			transaction.hset(public, "token", token);
			transaction.hset(public, "revoke_token", revoke_token);
			transaction.bgsave();
			transaction.exec(function(err) {
				callback(err, token, revoke_token);
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
	var public = uuid.v4();
	console.log("request:");

	var public = path.normalize(req.url).substr(path.sep.length);

	self._redis.hget(public, "revertToken", function(err, revertToken) {
		if(err)
			return self.error(err, res);
		var submittedToken = req.headers[process.config.tokenHeader];
		var tokenMissing = submittedToken == null;
		var authFailed = submittedToken != revertToken;

		if(tokenMissing) {
			// no token has been submitted
			res.writeHead(401);
			return res.end("Token required");
		}
		if(authFailed) {
			// Invalid token
			res.writeHead(403);
			return res.end("Invalid token");
		}
		self._redis.hdel(public, function(err) {
			if(err)
				return self.error(err, res);
			// successfully deleted
			res.writeHead(204);
			res.end();
		})
	
	});
}


RequestHandler.prototype.uploadFile = function(req, res) {
	var self = this;
	var token = null;
	var hasFile = false;

	var p = req.url.split(path.sep);
	var public = p[1];
	var chunkname = p[2];

	if(token === undefined || public === undefined)
		return self.error(new Error(), res);

	var submittedToken = req.headers[process.config.tokenHeader];

	var tokenMissing = submittedToken == null;
	if(tokenMissing) {
		// no token submitted
		res.writeHead(401);
		return res.end("Revoke token required");
	}

	self._redis.hget(public, 'token', function(err, storedToken) {
		if(err) {
			return self.error(err, res);
		}
		else if(storedToken === null) {
			// invalid (unused) storage volume id (public)
			res.writeHead(404);
			return res.end("Unknown Storage Volume");
		}
		else if(storedToken === submittedToken) {
			var saveTo = path.join(process.config.dataDir, public, chunkname);
			req.pipe(fs.createWriteStream(saveTo));
			req.on('end', function() {
				res.writeHead(200);
				res.end("Upload successful");
			});
		}
		else {
			// token is incorrect
			res.writeHead(403);
			res.end("Invalid token");
		}
	});
}

RequestHandler.prototype.error = function(err, res) {
	console.log(err);
	if(res) {
		res.writeHead(500);
		res.end("Internal server error");
	}
}
module.exports = RequestHandler;
