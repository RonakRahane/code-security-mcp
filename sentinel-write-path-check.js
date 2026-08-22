// Temporary file for verifying the Sentinel PR review write path.
// It is deleted along with the branch as soon as the check finishes.
const hash = crypto.createHash("md5").update(password).digest("hex");
module.exports = { hash };
