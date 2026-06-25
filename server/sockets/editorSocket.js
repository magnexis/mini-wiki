const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('../middleware/authMiddleware');

function authenticateSocket(socket, next) {
  const token =
    socket.handshake.auth?.token ||
    (socket.handshake.headers.authorization?.startsWith('Bearer ')
      ? socket.handshake.headers.authorization.slice(7)
      : '');

  if (!token) {
    return next(new Error('Authentication required'));
  }

  try {
    const payload = jwt.verify(token, getJwtSecret());
    socket.data.user = { id: payload.id, username: payload.username };
    return next();
  } catch {
    return next(new Error('Invalid or expired token'));
  }
}

function registerEditorSocket(io) {
  io.use(authenticateSocket);

  io.on('connection', (socket) => {
    socket.on('join-page', ({ pageId }) => {
      const userId = socket.data.user?.id;
      if (!pageId || !userId) return;
      socket.join(`page:${pageId}`);
      socket.to(`page:${pageId}`).emit('presence', {
        type: 'join',
        userId,
        at: Date.now()
      });
    });

    socket.on('leave-page', ({ pageId }) => {
      const userId = socket.data.user?.id;
      if (!pageId || !userId) return;
      socket.leave(`page:${pageId}`);
      socket.to(`page:${pageId}`).emit('presence', {
        type: 'leave',
        userId,
        at: Date.now()
      });
    });

    socket.on('content-change', ({ pageId, content }) => {
      const userId = socket.data.user?.id;
      if (!pageId || !userId) return;
      socket.to(`page:${pageId}`).emit('remote-content-change', {
        content,
        userId,
        timestamp: Date.now()
      });
    });

    socket.on('like-update', ({ pageId, likes }) => {
      if (!pageId) return;
      socket.to(`page:${pageId}`).emit('remote-like-update', { likes });
    });

    socket.on('view-update', ({ pageId, views }) => {
      if (!pageId) return;
      socket.to(`page:${pageId}`).emit('remote-view-update', { views });
    });
  });
}

module.exports = registerEditorSocket;