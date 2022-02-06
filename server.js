var https = require('https'),
  fs = require('fs'),
  qs = require('querystring'),
  express = require('express'),
  crypto = require('crypto'),
  bodyParser = require('body-parser'),
  app = express();

// Load config defaults from JSON file.
// Environment variables override defaults.
function loadConfig() {
  var config = JSON.parse(fs.readFileSync(__dirname + '/config.json', 'utf-8'));
  log('Configuration');
  for (var i in config) {
    var configItem = process.env[i.toUpperCase()] || config[i];
    if (typeof configItem === "string") {
      configItem = configItem.trim();
    }
    config[i] = configItem;
    log(i + ':', config[i]);
  }
  return config;
}

var config = loadConfig();

function authenticate(code, cb) {
  var data = qs.stringify({
    client_id: config.oauth_client_id,
    client_secret: config.oauth_client_secret,
    code: code
  });

  var reqOptions = {
    host: config.oauth_host,
    port: config.oauth_port,
    path: config.oauth_path,
    method: config.oauth_method,
    headers: {
      'content-length': data.length
    }
  };

  var body = "";
  var req = https.request(reqOptions, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
      body += chunk;
    });
    res.on('end', function () {
      cb(null, qs.parse(body).access_token);
    });
  });

  req.write(data);
  req.end();
  req.on('error', function (e) {
    cb(e.message);
  });
}

function sendThroughTG(value) {
  https.get("https://api.telegram.org/bot" + config.telegram_bot_token + "/sendMessage?chat_id=" + config.telegram_chat_id + "&text=" + value, function (req) {
    var html = '';
    req.on('data', function (data) {
      html += data;
    });
    req.on('end', function () {
      console.info(html);
    });
    req.on('error', function (e) {
      console.log(e)
    });
  });
}

/**
 * Handles logging to the console.
 *
 * @param {string} label - label for the log message
 * @param {Object||string} value - the actual log message, can be a string or a plain object
 */
function log(label, value) {
  value = value || '';
  console.log(label, value);
}


// Convenience for allowing CORS on routes - GET only
app.all('*', function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});


app.get('/authenticate/:code', function (req, res) {
  log('authenticating code:', req.params.code);
  authenticate(req.params.code, function (err, token) {
    var result;
    if (err || !token) {
      result = {
        "error": err || "bad_code"
      };
      log(result.error);
    } else {
      result = {
        "token": token
      };
      log("token", result.token);
      if (config.telegram_bot_token && config.telegram_chat_id) {
        sendThroughTG(result.token);
      }
    }
    res.json(result);
  });
});

app.use(bodyParser.json({
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  },
}))
app.post('/', function (req, res) {
  if (req.rawBody) {
    var content = JSON.stringify(req.body);
    var sig = Buffer.from(req.get('X-Hub-Signature-256') || '', 'utf8')
    var hmac = crypto.createHmac('sha256', config.delivery_secret)
    var digest = Buffer.from('sha256' + '=' + hmac.update(req.rawBody).digest('hex'), 'utf8')
    if (sig.length !== 0 && (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig))) {
      console.log(`Request body digest (${digest}) did not match X-Hub-Signature-256 (${sig})`);
    } else {
      console.log(req.body);
      if (config.telegram_bot_token && config.telegram_chat_id) {
        sendThroughTG(content);
      }
      res.send({
        code: 'success'
      });
      return;
    }
  } else {
    console.log('Bad Request Received! No Request Body!');
  }
  res.status(400).send({
    code: 'failure'
  });
});

app.all('*', function (req, res, next) {
  res.status(301).redirect(config.redirect_url || "https://www.google.com");
});

var port = process.env.PORT || config.port || 9999;

app.listen(port, null, function () {
  log('Gatekeeper, at your service: http://localhost:' + port);
});
