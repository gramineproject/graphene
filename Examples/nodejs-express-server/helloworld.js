const express = require('express')
const app = express()
const args = process.argv;

if (args == null || args.length != 3) {
  console.log('Error: The only argument required is the port number.')
  return;
}

const port = process.argv[2];

if (isNaN(port)) {
  console.log('Error: Port argument is not a number.')
  return;
}

app.get('/', (req, res) => res.send('Hello World!'))

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
