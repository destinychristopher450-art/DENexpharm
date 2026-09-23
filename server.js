const express = require('express');
const path = require('path');
const app = express();

const APP_VERSION = "1.0.0";

// Middleware configuration
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Custom header middleware
app.use((req, res, next) => {
  res.setHeader("X-DENexpharm-Version", APP_VERSION);
  next();
});

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, "public")));
