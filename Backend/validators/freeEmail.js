const freeList = require("./freeEmailList.json");

exports.checkFreeEmail = (email) => {
  const domain = email.split("@")[1].toLowerCase();
  return freeList.includes(domain);
};
