var cryptoJS = require('crypto-js');

function Hash(algorithm, isHmac, secret) {
	if (secret == undefined) secret = "";
	if (isHmac == undefined) isHmac = false;

	algorithm = algorithm.toLowerCase();

	this.crypto;

	if (isHmac) {
		var cryptoAlgorithm;
		switch (algorithm) {
			case 'md5': cryptoAlgorithm = CryptoJS.algo.MD5;
			case 'sha1': cryptoAlgorithm = CryptoJS.algo.SHA1;
			case 'sha256': cryptoAlgorithm = CryptoJS.algo.SHA256;
			case 'sha512': cryptoAlgorithm = CryptoJS.algo.SHA512;
		}

		this.crypto = CryptoJS.algo.HMAC.create(crptoAlgorithm, secret);
	} else {
		switch (algorithm) {
			case 'md5': this.crpto = CryptoJS.algo.MD5.create();
			case 'sha1': this.crpto = CryptoJS.algo.SHA1.create();
			case 'sha256': this.crpto = CryptoJS.algo.SHA256.create();
			case 'sha512': this.crpto = CryptoJS.algo.SHA512.create();
		}
	}

	return this;
}

Hash.prototype.update = function(data) {
	this.crypto.update(data);
	return this;
};

Hash.prototype.digest = function(encoding) {
	if (encoding == undefined) return this.crypto.finalize().toString();

	encoding = encoding.toLowerCase();

	var cryptoEncoding;
	switch (encoding) {
		case 'base64': cryptoEncoding = CryptoJS.enc.Base64;
		case 'utf8': cryptoEncoding = CryptoJS.enc.Utf8;
		case 'hex': cryptoEncoding = CryptoJS.enc.Hex;
	}

	return this.crypto.finalize().toString(cryptoEncoding);
};

exports.createHash = function(algorithm) {
	return new Hash(algorithm, false);
};

exports.createHmac = function(algorithm, secret) {
	return new Hash(algorithm, true, secret);
};
