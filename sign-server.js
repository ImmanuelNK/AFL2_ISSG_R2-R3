const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

const users = new Map();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  // setelah connect, user dikirim langsung ke server init
  socket.emit("init", Array.from(users.entries()));

  // setelah client connect, secara otomatis maka username dan public key akan ter regist
  socket.on("registerPublicKey", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);

    // user dan public key yang akan dikirim
    io.emit("newUser", { username, publicKey });
  });

  socket.on("message", (data) => {
    const { username, message, signature } = data;
    io.emit("message", { username, message, signature });
  });
  

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});