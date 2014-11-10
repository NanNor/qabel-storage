module.exports = {
	port: 8000,
	bind: '127.0.0.1',
	dataDir: __dirname + "/data",
	redisHost: '127.0.0.1',
	redisPort: 6379,
	redisDb: 0,
	uriPrefix: "/data",
	uriNew: "/_new",

	storageCreater: "sh/newStorage_dir.sh",
	storageRevoker: "sh/rmStorage_dir.sh",

	creater_ip_whitelist: [ "5.9.68.29" ]
}
