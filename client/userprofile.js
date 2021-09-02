var myHeaders = new Headers();
myHeaders.set('Cache-Control', 'no-store');
var urlParams = new URLSearchParams(window.location.search);
var tokens;
var domain = 'authorization-user-pool-domain';
var region = 'us-east-1';
var appClientId = 'e7lasra723e2dc7fig6mt3248gq';
var userPoolId = 'us-east-12_7xJbscdn3AF';
var redirectURI = 'https://d2qs4125ez97i.cloudfront.net/';
const decodePayload = (payload) => {
  const cleanedPayload = payload.replace(/-/g, '+').replace(/_/g, '/');
  const decodedPayload = atob(cleanedPayload);
  const uriEncodedPayload = Array.from(decodedPayload).reduce((acc, char) => {
    const uriEncodedChar = ('00' + char.charCodeAt(0).toString(16)).slice(-2);
    return `${acc}%${uriEncodedChar}`;
  }, '');

  const jsonPayload = decodeURIComponent(uriEncodedPayload);
  return JSON.parse(jsonPayload);
};

const parseJWTHeader = (token) => {
  const [header, payload, signature] = token.split('.');
  const jsonHeader = decodePayload(header);

  return jsonHeader;
};
const getRandomString = () => {
  const randomItems = new Uint32Array(28);
  crypto.getRandomValues(randomItems);
  const binaryStringItems = randomItems.map(
    (dec) => `0${dec.toString(16).substr(-2)}`
  );

  return binaryStringItems.reduce((acc, item) => `${acc}${item}`, '');
};
const encryptStringWithSHA256 = async (str) => {
  const PROTOCOL = 'SHA-256';
  const textEncoder = new TextEncoder();
  const encodedData = textEncoder.encode(str);

  return crypto.subtle.digest(PROTOCOL, encodedData);
};
const hashToBase64url = (arrayBuffer) => {
  const items = new Uint8Array(arrayBuffer);
  const stringifiedArrayHash = items.reduce(
    (acc, i) => `${acc}${String.fromCharCode(i)}`,
    ''
  );
  const decodedHash = btoa(stringifiedArrayHash);
  const base64URL = decodedHash
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return base64URL;
};

async function main() {
  var code = urlParams.get('code');
  if (code == null) {
    var state = getRandomString();
    sessionStorage.setItem('pkce_state', state);
    var code_verifier = getRandomString();
    sessionStorage.setItem('code_verifier', code_verifier);
    var arrayHash = await encryptStringWithSHA256(code_verifier);
    var code_challenge = hashToBase64url(arrayHash);
    sessionStorage.setItem('code_challenge', code_challenge);
    location.href =
      'https://' +
      domain +
      '.auth.' +
      region +
      '.amazoncognito.com/oauth2/authorize?response_type=code&state=' +
      state +
      '&client_id=' +
      appClientId +
      '&redirect_uri=' +
      redirectURI +
      '&scope=openid&code_challenge_method=S256&code_challenge=' +
      code_challenge;
  } else {
    state = urlParams.get('state');
    if (sessionStorage.getItem('pkce_state') != state) {
      alert('Invalid state');
    } else {
      code_verifier = sessionStorage.getItem('code_verifier');
      await fetch(
        'https://' +
          domain +
          '.auth.' +
          region +
          '.amazoncognito.com/oauth2/token?grant_type=authorization_code&client_id=' +
          appClientId +
          '&code_verifier=' +
          code_verifier +
          '&redirect_uri=' +
          redirectURI +
          '&code=' +
          code,
        {
          method: 'post',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }
      )
        .then((response) => {
          return response.json();
        })
        .then((data) => {
          tokens = data;
          var idVerified = verifyToken(tokens.id_token);
          Promise.resolve(idVerified).then(function (value) {
            if (value.localeCompare('verified')) {
              alert('Invalid ID Token - ' + value);
              return;
            }
          });
          document.getElementById('id_token').innerHTML = JSON.stringify(
            parseJWTPayload(tokens.id_token),
            null,
            '\t'
          );
          document.getElementById('access_token').innerHTML = JSON.stringify(
            parseJWTPayload(tokens.access_token),
            null,
            '\t'
          );
        });
      await fetch(
        'https://' +
          domain +
          '.auth.' +
          region +
          '.amazoncognito.com/oauth2/userInfo',
        {
          method: 'post',
          headers: { authorization: 'Bearer ' + tokens.access_token },
        }
      )
        .then((response) => {
          return response.json();
        })
        .then((data) => {
          document.getElementById('userInfo').innerHTML = JSON.stringify(
            data,
            null,
            '\t'
          );
        });
    }
  }
}
main();
