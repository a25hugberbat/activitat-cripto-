const { Server } = require('socket.io')

const io = new Server(3000, { cors: { origin: '*' } })

io.on('connection', (socket) => {
  console.log('Un navegador s\'ha connectat')

  socket.on('claus', (dades) => {
    socket.broadcast.emit('claus', dades)
  })

  socket.on('missatge', (dades) => {
    socket.broadcast.emit('missatge', dades)
  })
})