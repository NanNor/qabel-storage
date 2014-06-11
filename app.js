var http = require("http");
var async = require("async");
var redis = require("redis");
var connect = require("connect");
var dirlist = require('dirlist');


var RequestHandler = require('./app/requestHandler.js');

process.config = require("./config.js");
process.root = __dirname;

var redisClient = redis.createClient(process.config.redisPort, process.config.redisHost);

var reqHandler = new RequestHandler(redisClient);

var app = connect()
	.use(connect.logger('dev'))
	.use(connect.query())
	.use(process.config.uriPrefix, reqHandler.handle)
	.use(process.config.uriPrefix, connect.static(process.config.dataDir))
	.use(process.config.uriPrefix, dirlist(process.config.dataDir));

http.createServer(app).listen(process.config.port, process.config.bind);

process.on('uncaughtException', function(err) {
	console.log("Error: " + err);
})
