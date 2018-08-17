const mongoose = require('mongoose')

mongoose.connect('mongodb://127.0.0.1:27017/api', { useNewUrlParser: true })
mongoose.Promise = global.Promise

module.exports = mongoose
