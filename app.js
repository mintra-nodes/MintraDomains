const dotenv = require('dotenv');

dotenv.config();

const express = require('express');

const session = require('express-session');

const passport = require('passport');

const DiscordStrategy = require('passport-discord').Strategy;

const db = require('./database');

const { createSubdomain, editSubdomain, deleteSubdomain } = require('./cloudflare');

const domains = process.env.DOMAINS ? process.env.DOMAINS.split(',') : [];

const zoneIds = process.env.ZONE_IDS ? process.env.ZONE_IDS.split(',') : [];

const app = express();

app.set('trust proxy', 1);

app.use(

  session({

    secret: process.env.SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {

      secure: true,

      httpOnly: true,

      maxAge: 1000 * 60 * 60 * 24,

    },

  })

);

passport.use(

  new DiscordStrategy(

    {

      clientID: process.env.DISCORD_CLIENT_ID,

      clientSecret: process.env.DISCORD_CLIENT_SECRET,

      callbackURL: process.env.DISCORD_CALLBACK_URL,

      scope: ['identify','guilds.join'],

    },

    (accessToken, refreshToken, profile, done) => {

      if (!profile || !profile.id) {

        console.error('Invalid Discord profile:', profile);

        return done(new Error('Invalid Discord profile'));

      }

      return done(null, { ...profile, accessToken });

    }

  )

);

passport.serializeUser((user, done) => {

  done(null, user);

});

passport.deserializeUser((user, done) => {

  done(null, user);

});

app.use(passport.initialize());

app.use(passport.session());

app.set('view engine', 'ejs');

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(express.static('public'));

app.use((req, res, next) => {

  res.setHeader('X-Content-Type-Options', 'nosniff');

  res.setHeader('X-Frame-Options', 'DENY');

  res.setHeader('X-XSS-Protection', '1; mode=block');

  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  next();

});

const ensureAuth = (req, res, next) => {

  if (req.isAuthenticated() && req.user && req.user.id) {

    return next();

  }

  console.log('Authentication failed:', req.isAuthenticated(), req.user);

  res.redirect('/auth/login');

};

const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({

  windowMs: 15 * 60 * 1000,

  max: 10000,

  trustProxy: true,

  handler: (req, res) => {

    res.status(429).json({

      success: false,

      message: 'Too many requests, please try again later.',

    });

  },

});

const authLimiter = rateLimit({

  windowMs: 15 * 60 * 1000,

  max: 5,

});

const referralLimiter = rateLimit({

  windowMs: 15 * 60 * 1000,

  max: 10,

  handler: (req, res) => {

    res.status(429).json({

      success: false,

      message: 'Too many referral attempts, please try again later.',

    });

  },

});

app.use('/auth/', authLimiter);

app.use('/referral/', referralLimiter);

const validateSubdomainOwnership = (req, res, next) => {

  if (!req.user || !req.user.id) {

    console.error('No user in validateSubdomainOwnership:', req.user);

    return res.status(401).json({ success: false, message: 'Unauthorized' });

  }

  db.getUserSubdomains(req.user.id, (subdomains) => {

    const { subdomain } = req.query;

    const parts = subdomain?.split('.') || [];

    const name = parts.slice(0, -2).join('.');

    const domain = parts.slice(-2).join('.');

    const owns = subdomains.some(

      (s) =>

        s.subdomain.toLowerCase() === name?.toLowerCase() &&

        s.domain.toLowerCase() === domain?.toLowerCase()

    );

    if (!owns) {

      console.log(`User ${req.user.id} does not own ${subdomain}`);

      return res.status(403).json({ success: false, message: 'Forbidden' });

    }

    next();

  });

};

const validateInput = (req, res, next) => {

  const { subdomain, domain, ipv4, port } = req.body;

  if (!subdomain || !domain || !ipv4 || !port) {

    return res.status(400).json({ success: false, message: 'All fields are required' });

  }

  if (port < 1 || port > 65535) {

    return res.status(400).json({ success: false, message: 'Port must be between 1-65535' });

  }

  if (!domains.includes(domain)) {

    return res.status(400).json({ success: false, message: 'Invalid domain' });

  }

  next();

};

app.get('/', (req, res) => {

  if (req.isAuthenticated()) {

    return res.redirect('/dashboard');

  }

  res.render('login');

});

app.get('/get_subdomain_info', ensureAuth, apiLimiter, validateSubdomainOwnership, (req, res) => {

  const { subdomain } = req.query;

  if (!subdomain) {

    return res.status(400).json({ success: false, message: 'Subdomain parameter missing.' });

  }

  const parts = subdomain.trim().split('.');

  const name = parts.slice(0, -2).join('.');

  const domain = parts.slice(-2).join('.');

  db.getUserSubdomains(req.user.id, (subdomains) => {

    const subdomainInfo = subdomains.find(

      (s) =>

        s.subdomain.toLowerCase() === name.toLowerCase() &&

        s.domain.toLowerCase() === domain.toLowerCase()

    );

    if (subdomainInfo) {

      res.json({ success: true, subdomainInfo });

    } else {

      res.status(404).json({

        success: false,

        message: 'Subdomain not found.',

        debug: {

          searchedFor: { name, domain },

          availableSubdomains: subdomains.map((s) => `${s.subdomain}.${s.domain}`),

        },

      });

    }

  });

});

async function addUserToGuild(userId, accessToken, retries = 3, delay = 1000) {

  for (let i = 0; i < retries; i++) {

    try {

      const response = await fetch(`https://discord.com/api/guilds/1359527121617162393/members/${userId}`, {

        method: 'PUT',

        headers: {

          Authorization: `Bot ${process.env.BOT_TOKEN}`,

          'Content-Type': 'application/json',

        },

        body: JSON.stringify({ access_token: accessToken }),

      });

      if (response.ok) {

        console.log(`User ${userId} added to guild successfully`);

        return true;

      } else {

        const errorText = await response.text();

        console.error(`Attempt ${i + 1} failed to add user ${userId} to guild:`, errorText);

      }

    } catch (error) {

      console.error(`Attempt ${i + 1} error adding user ${userId} to guild:`, error.message);

    }

    if (i < retries - 1) {

      await new Promise((resolve) => setTimeout(resolve, delay));

    }

  }

  console.error(`Failed to add user ${userId} to guild after ${retries} attempts`);

  return false;

}

async function upsertUser(discordUserId, username) {

  return new Promise((resolve, reject) => {

    db.get('SELECT * FROM users WHERE discord_user_id = ?', [discordUserId], (err, row) => {

      if (err) {

        console.error('Error checking user:', err);

        return reject(err);

      }

      if (row) {

        if (row.username !== username) {

          db.run(

            'UPDATE users SET username = ? WHERE discord_user_id = ?',

            [username, discordUserId],

            (err) => {

              if (err) {

                console.error('Error updating username:', err);

                return reject(err);

              }

              console.log(`Updated username for user ${discordUserId}`);

              resolve(row);

            }

          );

        } else {

          resolve(row);

        }

      } else {

        db.run(

          'INSERT INTO users (discord_user_id, username, max_subdomains, coins) VALUES (?, ?, ?, ?)',

          [discordUserId, username, 1, 0],

          (err) => {

            if (err) {

              console.error('Error creating user:', err);

              return reject(err);

            }

            console.log(`Created new user ${discordUserId}`);

            resolve({ discord_user_id: discordUserId, username, max_subdomains: 1, coins: 0 });

          }

        );

      }

    });

  });

}

app.get('/auth/register', passport.authenticate('discord'));

app.get(

  '/auth/register/callback',

  passport.authenticate('discord', { failureRedirect: '/' }),

  async (req, res) => {

    if (!req.user || !req.user.id || !req.user.username) {

      console.error('Invalid user data in register callback:', req.user);

      return res.redirect('/');

    }

    try {

      await addUserToGuild(req.user.id, req.user.accessToken);

      await upsertUser(req.user.id, req.user.username);

      res.redirect('/dashboard');

    } catch (error) {

      console.error('Error in register callback:', error);

      res.redirect('/dashboard');

    }

  }

);

app.get(

  '/auth/login',

  passport.authenticate('discord', {

    callbackURL: process.env.DISCORD_LOGIN_CALLBACK_URL || process.env.DISCORD_CALLBACK_URL,

  })

);

app.get(

  '/auth/callback',

  passport.authenticate('discord', {

    failureRedirect: '/',

    callbackURL: process.env.DISCORD_LOGIN_CALLBACK_URL || process.env.DISCORD_CALLBACK_URL,

  }),

  async (req, res) => {

    if (!req.user || !req.user.id || !req.user.username) {

      console.error('Invalid user data in login callback:', req.user);

      return res.redirect('/');

    }

    try {

      await addUserToGuild(req.user.id, req.user.accessToken);

      await upsertUser(req.user.id, req.user.username);

      res.redirect('/dashboard');

    } catch (error) {

      console.error('Error in login callback:', error);

      res.redirect('/dashboard');

    }

  }

);

app.get('/auth/logout', (req, res) => {

  req.logout((err) => {

    if (err) console.error('Logout error:', err);

    res.redirect('/');

  });

});

app.get('/dashboard', ensureAuth, (req, res) => {

  db.get(

    'SELECT max_subdomains, coins, referral_code FROM users WHERE discord_user_id = ?',

    [req.user.id],

    (err, row) => {

      if (err || !row) {

        console.error('Error fetching user data for dashboard:', err, row);

        return res.redirect('/');

      }

      const max_subdomains = row.max_subdomains || 1;

      const coins = row.coins || 0;

      const referralCode = row.referral_code || null;

      req.user.max_subdomains = max_subdomains;

      req.user.coins = coins;

      req.user.referralCode = referralCode;

      db.getUserSubdomains(req.user.id, (subdomains) => {

        res.render('dashboard', { user: req.user, subdomains });

      });

    }

  );

});

app.get('/shop', ensureAuth, (req, res) => {

  db.get('SELECT coins FROM users WHERE discord_user_id = ?', [req.user.id], (err, row) => {

    if (err) {

      console.error('Error fetching coins for shop:', err);

      return res.status(500).json({ success: false, message: 'Database error' });

    }

    res.render('shop', {

      user: { ...req.user, coins: row ? row.coins : 0 },

    });

  });

});

app.post('/shop/purchase', ensureAuth, async (req, res) => {

  const { itemId } = req.body;

  const items = {

    subdomain_slot: { price: 1000, maxSubdomains: 1 },

  };

  const item = items[itemId];

  if (!item) return res.json({ success: false, message: 'Invalid item' });

  db.get('SELECT coins FROM users WHERE discord_user_id = ?', [req.user.id], (err, user) => {

    if (err || !user) {

      console.error('Error fetching user for purchase:', err);

      return res.json({ success: false, message: 'User not found' });

    }

    if (user.coins < item.price) {

      return res.json({ success: false, message: 'Insufficient coins' });

    }

    db.run(

      'UPDATE users SET coins = coins - ?, max_subdomains = max_subdomains + ? WHERE discord_user_id = ?',

      [item.price, item.maxSubdomains, req.user.id],

      (err) => {

        if (err) {

          console.error('Error processing purchase:', err);

          return res.json({ success: false, message: 'Purchase failed' });

        }

        res.json({ success: true, message: 'Purchase successful' });

      }

    );

  });

});

app.post('/referral/set', ensureAuth, (req, res) => {

  const { code } = req.body;

  if (!code || code.length < 1 || code.length > 32) {

    return res.json({ success: false, message: 'Invalid code length' });

  }

  if (!/^[a-zA-Z0-9]+$/.test(code)) {

    return res.json({ success: false, message: 'Invalid code format' });

  }

  db.setReferralCode(req.user.id, code, (success, message) => {

    res.json({ success, message: message || (success ? 'Code set' : 'Code taken') });

  });

});

app.post('/referral/use', ensureAuth, (req, res) => {

  const { code } = req.body;

  if (!code) return res.json({ success: false, message: 'No code provided' });

  db.useReferralCode(code, req.user.id, (success, message) => {

    res.json({ success, message: message || (success ? 'Code applied (+100 coins)' : 'Invalid code') });

  });

});

app.post('/create_subdomain', ensureAuth, validateInput, async (req, res) => {

  const { subdomain, domain, ipv4, port } = req.body;

  const discordUserId = req.user.id;

  db.getMaxSubdomains(discordUserId, (maxSubdomains) => {

    db.countUserSubdomains(discordUserId, async (subdomainCount) => {

      if (subdomainCount >= maxSubdomains) {

        return res.json({ success: false, message: 'You have reached the maximum number of subdomains allowed.' });

      }

      try {

        const result = await createSubdomain(subdomain, domain, ipv4, port);

        if (result.success) {

          db.saveSubdomain(discordUserId, subdomain, domain, ipv4, port);

          res.json({ success: true });

        } else {

          res.json({ success: false, message: 'Failed to create subdomain' });

        }

      } catch (error) {

        console.error('Error creating subdomain:', error);

        res.json({ success: false, message: error.message });

      }

    });

  });

});

app.post('/edit_subdomain', ensureAuth, async (req, res) => {

  const { oldSubdomain, oldDomain, newSubdomain, newDomain, newIpv4, newPort } = req.body;

  try {

    const subdomains = await new Promise((resolve) => {

      db.getUserSubdomains(req.user.id, (subdomains) => resolve(subdomains));

    });

    const existingSubdomain = subdomains.find(

      (s) =>

        s.subdomain.toLowerCase() === oldSubdomain.toLowerCase() &&

        s.domain.toLowerCase() === oldDomain.toLowerCase()

    );

    if (!existingSubdomain) {

      return res.status(404).json({ success: false, message: 'Subdomain not found' });

    }

    const deleteResult = await deleteSubdomain(oldSubdomain, oldDomain);

    if (!deleteResult.success) {

      return res.json({ success: false, message: 'Failed to delete old DNS records' });

    }

    const createResult = await createSubdomain(

      newSubdomain || oldSubdomain,

      newDomain || oldDomain,

      newIpv4 || existingSubdomain.ipv4,

      newPort || existingSubdomain.port

    );

    if (!createResult.success) {

      await createSubdomain(oldSubdomain, oldDomain, existingSubdomain.ipv4, existingSubdomain.port);

      return res.json({ success: false, message: 'Failed to create new DNS records' });

    }

    await new Promise((resolve, reject) => {

      db.updateSubdomain(

        req.user.id,

        oldSubdomain,

        oldDomain,

        newSubdomain || oldSubdomain,

        newDomain || oldDomain,

        newIpv4 || existingSubdomain.ipv4,

        newPort || existingSubdomain.port,

        (err) => {

          if (err) reject(err);

          else resolve();

        }

      );

    });

    res.json({ success: true, message: 'Subdomain updated successfully' });

  } catch (error) {

    console.error('Error editing subdomain:', error);

    res.json({ success: false, message: error.message });

  }

});

const validateApiKey = (req, res, next) => {

  const apiKey = req.headers['x-api-key'];

  if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {

    return res.status(401).json({ success: false, message: 'Invalid API key' });

  }

  next();

};

app.post('/api/admin/subdomains', validateApiKey, (req, res) => {

  const { userId, amount } = req.body;

  if (!userId || typeof amount !== 'number') {

    return res.status(400).json({ success: false, message: 'Invalid parameters' });

  }

  db.run(

    'UPDATE users SET max_subdomains = max_subdomains + ? WHERE discord_user_id = ?',

    [amount, userId],

    (err) => {

      if (err) {

        console.error('Error updating subdomain limit:', err);

        return res.status(500).json({ success: false, message: 'Database error' });

      }

      res.json({ success: true, message: 'Subdomain limit updated' });

    }

  );

});

app.post('/api/admin/coins', validateApiKey, (req, res) => {

  const { userId, amount } = req.body;

  if (!userId || typeof amount !== 'number') {

    return res.status(400).json({ success: false, message: 'Invalid parameters' });

  }

  db.updateUserCoins(userId, amount, (err) => {

    if (err) {

      console.error('Error updating coins:', err);

      return res.status(500).json({ success: false, message: 'Database error' });

    }

    res.json({ success: true, message: 'Coins updated' });

  });

});

app.delete('/delete_subdomain', ensureAuth, async (req, res) => {

  const { subdomain } = req.body;

  if (!subdomain) {

    return res.status(400).json({ success: false, message: 'No subdomain provided.' });

  }

  const parts = subdomain.split('.');

  if (parts.length < 3) {

    return res.status(400).json({ success: false, message: 'Invalid subdomain format.' });

  }

  const domain = parts.slice(-2).join('.');

  const name = parts.slice(0, -2).join('.');

  try {

    const subdomains = await new Promise((resolve) => {

      db.getUserSubdomains(req.user.id, (subdomains) => resolve(subdomains));

    });

    const exists = subdomains.some(

      (s) =>

        s.subdomain.toLowerCase() === name.toLowerCase() &&

        s.domain.toLowerCase() === domain?.toLowerCase()

    );

    if (!exists) {

      return res.status(404).json({ success: false, message: 'Subdomain not found.' });

    }

    const cloudflareResult = await deleteSubdomain(name, domain);

    if (!cloudflareResult.success) {

      return res.json({

        success: false,

        message: `Failed to delete DNS records: ${cloudflareResult.message}`,

      });

    }

    db.removeSubdomain(req.user.id, name, domain, (success) => {

      if (success) {

        res.json({

          success: true,

          message: 'Successfully deleted subdomain and DNS records',

        });

      } else {

        res.json({

          success: false,

          message: 'DNS records deleted but failed to update database',

        });

      }

    });

  } catch (error) {

    console.error('Error deleting subdomain:', error);

    res.json({

      success: false,

      message: `Error during deletion: ${error.message}`,

    });

  }

});

app.listen(1025, '0.0.0.0', () => console.log('Server running on http://0.0.0.0:1025'));