const roleList = require("./roleBasedList.json");

exports.checkRoleBased = (email) => {
  const username = email.split("@")[0].toLowerCase();
  return roleList.includes(username);
};
