const fs = require("fs");

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

function convertRawCertHex(rawCertHex = "") {
  return rawCertHex
    .replaceAll(":", "")
    .replaceAll(" ", "")
    .replaceAll("\n", "")
    .trim();
}

const publicKey = hexToBytes(
  convertRawCertHex(`04:5d:15:48:48:4c:22:91:ab:4c:45:70:1d:f7:f0:
  0b:20:4f:fb:72:3f:5e:50:55:87:e7:ed:cd:cd:62:
  69:54:e5:9f:c5:fb:f6:41:88:00:07:e7:10:68:10:
  a6:3d:a1:64:64:eb:d0:33:2c:64:ce:90:93:ae:ba:
  d4:f4:a8:91:db:a6:05:b8:57:cf:0f:6f:e6:6f:03:
  e6:6d:14:1e:df:8b:95:2a:98:78:2a:70:4e:36:31:
  a8:f2:d8:94:f5:74:e6`)
);

const prime = hexToBytes(
  convertRawCertHex(`8c:b9:1e:82:a3:38:6d:28:0f:5d:6f:7e:50:e6:
  41:df:15:2f:71:09:ed:54:56:b4:12:b1:da:19:7f:
  b7:11:23:ac:d3:a7:29:90:1d:1a:71:87:47:00:13:
  31:07:ec:53`)
);

const a = hexToBytes(
  convertRawCertHex(`7b:c3:82:c6:3d:8c:15:0c:3c:72:08:0a:ce:05:af:
  a0:c2:be:a2:8e:4f:b2:27:87:13:91:65:ef:ba:91:
  f9:0f:8a:a5:81:4a:50:3a:d4:eb:04:a8:c7:dd:22:
  ce:28:26`)
);

const b = hexToBytes(
  convertRawCertHex(`04:a8:c7:dd:22:ce:28:26:8b:39:b5:54:16:f0:44:
  7c:2f:b7:7d:e1:07:dc:d2:a6:2e:88:0e:a5:3e:eb:
  62:d5:7c:b4:39:02:95:db:c9:94:3a:b7:86:96:fa:
  50:4c:11`)
);

const generator = hexToBytes(
  convertRawCertHex(`04:1d:1c:64:f0:68:cf:45:ff:a2:a6:3a:81:b7:c1:
  3f:6b:88:47:a3:e7:7e:f1:4f:e3:db:7f:ca:fe:0c:
  bd:10:e8:e8:26:e0:34:36:d6:46:aa:ef:87:b2:e2:
  47:d4:af:1e:8a:be:1d:75:20:f9:c2:a4:5c:b1:eb:
  8e:95:cf:d5:52:62:b7:0b:29:fe:ec:58:64:e1:9c:
  05:4f:f9:91:29:28:0e:46:46:21:77:91:81:11:42:
  82:03:41:26:3c:53:15`)
);

const order = hexToBytes(
  convertRawCertHex(`8c:b9:1e:82:a3:38:6d:28:0f:5d:6f:7e:50:e6:
  41:df:15:2f:71:09:ed:54:56:b3:1f:16:6e:6c:ac:
  04:25:a7:cf:3a:b6:af:6b:7f:c3:10:3b:88:32:02:
  e9:04:65:65`)
);

const cofactor = hexToBytes("01");

fs.writeFileSync(
  "./csca/de/2011/cert.json",
  JSON.stringify({
    signatureAlgorithm: "ecdsa-with-SHA384",
    publicKey,
    prime,
    a,
    b,
    generator,
    order,
    cofactor,
  })
);
