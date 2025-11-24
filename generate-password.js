const bcrypt = require('bcrypt');

const newPassword = "autom@Xnovest1652";

const salt = bcrypt.genSaltSync(10);
const hashedPassword = bcrypt.hashSync(newPassword, salt);

console.log("====================================");
console.log("Your new password is:", newPassword);
console.log("====================================");
console.log("Copy this HASHED password to your database:");
console.log(hashedPassword);
console.log("====================================");