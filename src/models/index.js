const EmailCode = require("./EmailCode");
const User = require("./User");


User.hasOne(EmailCode)
EmailCode.belongsTo(User)