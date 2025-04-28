const sqlite3 = require('sqlite3').verbose();

const path = require('path');

const db = new sqlite3.Database(path.resolve(__dirname, 'Frac.db'), (err) => {

  if (err) {

    console.error('Error opening database:', err);

  } else {

    console.log('Database connected.');

    db.run(`CREATE TABLE IF NOT EXISTS subdomains (

      id INTEGER PRIMARY KEY AUTOINCREMENT,

      discord_user_id TEXT NOT NULL,

      subdomain TEXT NOT NULL,

      domain TEXT NOT NULL,

      ipv4 TEXT NOT NULL,

      port INTEGER NOT NULL,

      visits INTEGER DEFAULT 0

    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (

      discord_user_id TEXT PRIMARY KEY,

      username TEXT NOT NULL,

      max_subdomains INTEGER DEFAULT 1,

      coins INTEGER DEFAULT 0,

      referral_code TEXT UNIQUE,

      referred_by TEXT

    )`);

  }

});

function getUserSubdomains(discordUserId, callback) {

  db.all('SELECT * FROM subdomains WHERE discord_user_id = ?', [discordUserId], (err, rows) => {

    if (err) {

      console.error('Error fetching subdomains:', err);

      return callback([]);

    }

    callback(rows);

  });

}

function getUserSubdomainsAsync(discordUserId) {

  return new Promise((resolve, reject) => {

    db.all('SELECT * FROM subdomains WHERE discord_user_id = ?', [discordUserId], (err, rows) => {

      if (err) {

        console.error('Error fetching subdomains:', err);

        reject(err);

      } else {

        resolve(rows);

      }

    });

  });

}

function getMaxSubdomains(discordUserId, callback) {

  db.get('SELECT max_subdomains FROM users WHERE discord_user_id = ?', [discordUserId], (err, row) => {

    if (err) {

      console.error('Error fetching max subdomains:', err);

      return callback(1);

    }

    callback(row ? row.max_subdomains : 1);

  });

}

function countUserSubdomains(discordUserId, callback) {

  db.get('SELECT COUNT(*) as count FROM subdomains WHERE discord_user_id = ?', [discordUserId], (err, row) => {

    if (err) {

      console.error('Error counting user subdomains:', err);

      return callback(0);

    }

    callback(row.count);

  });

}

function saveSubdomain(discordUserId, subdomain, domain, ipv4, port) {

  db.run(`INSERT INTO subdomains (discord_user_id, subdomain, domain, ipv4, port) VALUES (?, ?, ?, ?, ?)`,

    [discordUserId, subdomain, domain, ipv4, port], (err) => {

      if (err) {

        console.error('Error saving subdomain:', err);

      } else {

        console.log('Subdomain saved successfully.');

      }

    });

}

function updateSubdomain(discordUserId, oldSubdomain, oldDomain, newSubdomain, newDomain, newIpv4, newPort, callback) {

  const query = `

    UPDATE subdomains 

    SET subdomain = ?, 

        domain = ?, 

        ipv4 = ?, 

        port = ? 

    WHERE discord_user_id = ? 

    AND subdomain = ? 

    AND domain = ?`;

  db.run(query, 

    [newSubdomain, newDomain, newIpv4, newPort, discordUserId, oldSubdomain, oldDomain], 

    function(err) {

      if (err) {

        console.error('Error updating subdomain:', err);

        callback?.(err);

      } else {

        if (this.changes === 0) {

          console.error('No subdomain found to update');

          callback?.(new Error('No subdomain found to update'));

        } else {

          console.log('Subdomain updated successfully.');

          callback?.(null);

        }

      }

    }

  );

}

function removeSubdomain(discordUserId, subdomain, domain, callback) {

  db.run(`DELETE FROM subdomains WHERE discord_user_id = ? AND subdomain = ? AND domain = ?`,

    [discordUserId, subdomain, domain], (err) => {

      if (err) {

        console.error('Error deleting subdomain:', err);

        callback(false);

      } else {

        console.log('Subdomain removed successfully.');

        callback(true);

      }

    });

}

function getAllSubdomains(callback) {

  db.all('SELECT * FROM subdomains', (err, rows) => {

    if (err) {

      console.error('Error fetching all subdomains:', err);

      return callback([]);

    }

    callback(rows);

  });

}

function setReferralCode(userId, code, callback) {

  if (!code.match(/^[a-zA-Z0-9]{3,16}$/)) {

    return callback(false, 'Code must be 3-16 alphanumeric characters');

  }

  console.log('Setting referral code:', code, 'for user:', userId);

  db.run('INSERT OR IGNORE INTO users (discord_user_id, username, max_subdomains, coins) VALUES (?, ?, ?, ?)',

    [userId, 'User', 1, 0], (err) => {

      if (err) {

        console.error('Error creating user:', err);

        return callback(false, 'Database error');

      }

      db.get('SELECT * FROM users WHERE discord_user_id = ?', [userId], (err, user) => {

        if (err || !user) {

          console.error('User not found:', userId);

          return callback(false, 'User not found');

        }

        if (user.referral_code) {

          console.log('User already has referral code:', user.referral_code);

          return callback(false, 'Already set');

        }

        db.get('SELECT discord_user_id FROM users WHERE referral_code = ? COLLATE NOCASE', [code], (err, existing) => {

          if (err) {

            console.error('Error checking code:', err);

            return callback(false, 'Database error');

          }

          if (existing) {

            console.log('Code already taken:', code);

            return callback(false, 'Code taken');

          }

          db.serialize(() => {

            db.run('BEGIN TRANSACTION');

            db.run('UPDATE users SET referral_code = ? WHERE discord_user_id = ?', [code, userId], (err) => {

              if (err) {

                console.error('Error setting code:', err);

                db.run('ROLLBACK');

                return callback(false, 'Failed to set code');

              }

              db.run('COMMIT', (err) => {

                if (err) {

                  console.error('Commit failed:', err);

                  db.run('ROLLBACK');

                  return callback(false, 'Transaction failed');

                }

                db.get('SELECT referral_code FROM users WHERE discord_user_id = ?', [userId], (err, row) => {

                  if (err) {

                    console.error('Database error during verification:', err);

                    return callback(false, 'Database error during verification');

                  }

                  if (!row) {

                    console.error('No row found after setting code');

                    return callback(false, 'Code was not set properly');

                  }

                  console.log('Stored referral_code:', row.referral_code, 'Input code:', code);

                  if (row.referral_code.toLowerCase() !== code.toLowerCase()) {

                    console.error('Verification failed for code:', code);

                    return callback(false, 'Failed to verify code');

                  }

                  console.log('Referral code set successfully:', code);

                  callback(true, 'Code set successfully');

                });

              });

            });

          });

        });

      });

    });

}

function deleteReferralCode(userId, callback) {

  db.run('UPDATE users SET referral_code = NULL WHERE discord_user_id = ?', [userId], (err) => {

    callback(!err);

  });

}

function updateUserCoins(userId, amount, callback) {

  db.run('UPDATE users SET coins = coins + ? WHERE discord_user_id = ?', [amount, userId], callback);

}

function getReferralInfo(userId, callback) {

  db.get('SELECT referral_code, coins, referred_by FROM users WHERE discord_user_id = ?', [userId], callback);

}

function useReferralCode(code, newUserId, callback) {

  console.log('Attempting to use referral code:', code, 'for user:', newUserId);

  if (!code || !newUserId) {

    console.error('Invalid input: code or userId missing');

    return callback(false, 'Invalid input');

  }

  db.get('SELECT discord_user_id FROM users WHERE referral_code = ? COLLATE NOCASE', [code], (err, referrer) => {

    if (err) {

      console.error('Error finding referrer:', err);

      return callback(false, 'Database error');

    }

    if (!referrer) {

      console.error('No referrer found for code:', code);

      return callback(false, 'Invalid referral code');

    }

    console.log('Referrer found:', referrer.discord_user_id);

    if (referrer.discord_user_id === newUserId) {

      console.error('User attempted to use own code');

      return callback(false, 'Cannot use your own referral code');

    }

    db.get('SELECT referred_by FROM users WHERE discord_user_id = ?', [newUserId], (err, user) => {

      if (err) {

        console.error('Error checking user:', err);

        return callback(false, 'Database error');

      }

      if (user?.referred_by) {

        console.error('User already referred by:', user.referred_by);

        return callback(false, 'You have already used a referral code');

      }

      db.serialize(() => {

        db.run('BEGIN TRANSACTION');

        db.run('UPDATE users SET referred_by = ? WHERE discord_user_id = ?', [referrer.discord_user_id, newUserId], (err) => {

          if (err) {

            console.error('Error setting referrer:', err);

            db.run('ROLLBACK');

            return callback(false, 'Failed to set referrer');

          }

        });

        db.run('UPDATE users SET coins = coins + 100 WHERE discord_user_id = ?', [referrer.discord_user_id], (err) => {

          if (err) {

            console.error('Error awarding referrer coins:', err);

            db.run('ROLLBACK');

            return callback(false, 'Failed to award referrer coins');

          }

        });

        db.run('UPDATE users SET coins = coins + 100 WHERE discord_user_id = ?', [newUserId], (err) => {

          if (err) {

            console.error('Error awarding user coins:', err);

            db.run('ROLLBACK');

            return callback(false, 'Failed to award user coins');

          }

        });

        db.run('COMMIT', (err) => {

          if (err) {

            console.error('Commit failed:', err);

            db.run('ROLLBACK');

            return callback(false, 'Transaction failed');

          }

          console.log('Referral applied successfully for code:', code);

          callback(true, 'Referral code applied successfully');

        });

      });

    });

  });

}

module.exports = {

  get: (query, params, callback) => db.get(query, params, callback),

  run: (query, params, callback) => db.run(query, params, callback),

  getUserSubdomains,

  getUserSubdomainsAsync,

  getMaxSubdomains,

  countUserSubdomains,

  saveSubdomain,

  updateSubdomain,

  removeSubdomain,

  getAllSubdomains,

  setReferralCode,

  updateUserCoins,

  getReferralInfo,

  useReferralCode,

  deleteReferralCode

};