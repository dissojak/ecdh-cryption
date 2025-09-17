import app, { server } from './app.js';

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT} (with socket.io)`);
});
