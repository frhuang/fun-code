var requireHeaders = {
  'get': /^GET (\/[^\s]*)/,
  'upgrade': /^websocket$/,
  'connection': /^Upgrade$/,
  'host': /^(.+)$/,
  'origin': /^(.+)$/
};

var flashPolicy = '<cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>';
var keySha1Str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var keyBaseStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/**
 * base64编码
 * keyBaseStr为变换表
 */
function encode64(input) {
  input = escape(input);
  var output = "";
  var chr1, chr2, chr3 = "";
  var enc1, enc2, enc3, enc4 = "";
  var i = 0;
  do {
    chr1 = parseInt(input.substring(i, i += 2), 16);
    chr2 = parseInt(input.substring(i, i += 2), 16);
    chr3 = parseInt(input.substring(i, i += 2), 16);
    enc1 = chr1 >> 2;
    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
    enc4 = chr3 & 63;
    if (isNaN(chr2)) {
      enc3 = enc4 = 64;
    } else if (isNaN(chr3)) {
      enc4 = 64;
    }
    output = output + 
             keyBaseStr.charAt(enc1) + 
             keyBaseStr.charAt(enc2) + 
             keyBaseStr.charAt(enc3) + 
             keyBaseStr.charAt(enc4);
    chr1 = chr2 = chr3 = "";
    enc1 = enc2 = enc3 = enc4 = "";
  } while (i < input.length)
  return output;
}

/**
 * sha1加密
 */
var hexcase = 0;
var b64pad = "";
var chrsz = 8;

function hex_sha1(s) { return binb2hex(core_sha1(str2binb(s), s.length * chrsz)); }
function b64_sha1(s) { return binb2b64(core_sha1(str2binb(s), s.length * chrsz)); }
function str_sha1(s) { return binb2str(core_sha1(str2binb(s), s.length * chrsz)); }
function hex_hmac_sha1(key, data) { return binb2hex(core_hmac_sha1(key, data)); }
function b64_hmac_sha1(key, data) { return binb2b64(core_hmac_sha1(key, data)); }
function str_hmac_sha1(key, data) { return binb2str(core_hmac_sha1(key, data)); }

function sha1_vm_test() {
  return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

function core_sha1(x, len) {
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;
  var w = Array(80);
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;
  
  for (var i = 0; i < x.length; i += 16) {
    var olda = a, oldb = b, oldc = c, oldd = d, olde = e;
    for (var j = 0; j < 80; j++) {
      if (j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)), 
              safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }
    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);
}

function sha1_ft(t, b, c, d) {
  if (t < 20) return (b & c) | ((~b) & d);
  if (t < 40) return b ^ c ^ d;
  if (t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

function sha1_kt(t) {
  return t < 20 ? 1518500249 :
         t < 40 ? 1859775393 :
         t < 50 ? -1894007588 : -899497514;
}

function core_hmac_sha1(key, data) {
  var bkey = str2binb(key);
  if (bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);
  var ip = Array(16), op = Array(16);
  for (var i = 0; i < 16; i++) {
    ip[i] = bkey[i] ^ 0x36363636;
    op[i] = bkey[i] ^ 0x5C5C5C5C;
  }
  var hash = core_sha1(ip.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(op.concat(hash), 512 + 160);
}

function safe_add(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

function rol(num, cnt) {
  return (num << cnt) | (num >>> (32 - cnt));
}

function str2binb(str) {
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for (var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i % 32);
  return str;
}

function binb2Str(bin) {
  var str = "";
  var mask = (1 << chrsz) - 1;
  for (var i = 0; i < bin.length * 32; i += chrsz)
    str += String.foromCharCode((bin[i>>5] >>> (32 - chrsz - i % 32)) & mask);
  return str;
}

function binb2hex(binarray) {
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for (var i = 0; i < binarray.length * 4; i++) {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4) * 8 + 4)) & 0xF) + 
          hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4) * 8)) & 0xF);
  }
  return str;
}

function binb2b64(binarray) {
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var str = "";
  for (var i = 0; i < binarray.length * 4; i += 3) {
    var triplet = (((binarray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16)
                  | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8)
                  | ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    
    for (var j = 0; j < 4; j++) {
      if (i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6 * (3-j)) & 0x3F);
    }
  }
  return str;
}

exports.httpy = function(data, options, socket) {
  var _headers = data.split("\r\n");

  if (/<policy-file-request.*>/.exec(_headers[0])) {
    socket.write(options.flashPolicy);
    socket.end();
    return false;
  }

  var headers = {}, upgradeHead, len = _headers.length;

  if (_headers[0].match(/^GET/)) {
    headers["get"] = _headers[0];
  } else {
    socket.end()
    return false;
  }

  if (_headers[_headers.length - 1]) {
    upgradeHead = _headers[_headers.length - 1];
    len --;
  }
  while (--len) {
    var header = _headers[len];
    if (!header) continue;

    var sp = header.split(": ", 2);
    headers[sp[0].toLowerCase()] = sp[1];
  }

  if (headers["sec-websocket-key"]) {
    var key = headers["sec-websocket-key"] + keySha1Str;
    var keySha1 = hex_sha1(key);
    var keyBase = encode64(keySha1);
    var response = "HTTP/1.1 101 Switching Protocols\r\n";
    response += "Upgrade: websocket\r\n";
    response += "Connection: Upgrade\r\n";
    response += "Sec-WebSocket-Accept:" + keyBase + "\r\n\r\n";
    if (socket.destoryed == false && socket.writable == true && socket.readable == true) {
      socket.write(response);
    }
  }

  console.log('client connected from IP:' + socket.remoteAddress + "PORT:" + socket.remotePort);
  return true;
}