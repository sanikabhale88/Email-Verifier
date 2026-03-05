const disposableList = require("./disposable.json");

exports.checkDisposable = (email) => {
  const domain = email.split("@")[1].toLowerCase();
  return disposableList.includes(domain);
};
