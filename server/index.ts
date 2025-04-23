import express from 'express';
import session from 'express-session';
import { setupSecurity } from './middleware/security';
import { registerRoutes } from './routes';
import { storage } from './storage';

const app = express();
const port = process.env.PORT || 3000;

// Setup security middleware
setupSecurity(app);

// Session middleware
app.use(
  session({
    store: storage.sessionStore,
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  })
);

// Body parsing middleware
app.use(express.json());

// Register all routes
registerRoutes(app).then(server => {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}).catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
