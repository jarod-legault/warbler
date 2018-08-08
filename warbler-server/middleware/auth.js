require("dotenv").load();
const jwt = require("jsonwebtoken");

exports.loginRequired = function(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1]; // token comes in after space, i.e. "BEARER <token>"
    jwt.verify(token, process.env.SECRET_KEY, function(err, decoded) {
      if (decoded) {
        return next();
      } else {
        return next({
          status: 401, // 401 = unauthorized
          message: "Please log in first"
        });
      }
    });
  } catch (e) {
    return next({
      status: 401, // 401 = unauthorized
      message: "Please log in first"
    });
  }
};

exports.ensureCorrectUser = function(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1]; // token comes in after space, i.e. "BEARER <token>"
    jwt.verify(token, process.env.SECRET_KEY, function(err, decoded) {
      if(decoded && decoded.id === req.params.id) {
        return next();
      } else {
        return next({
          status: 401, // unauthorized
          message: "Unauthorized"
        });
      }
    })
  } catch (e) {
    return next({
      status: 401, // unauthorized
      message: "Unauthorized"
    });
  }
};