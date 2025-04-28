![Fractal](https://cdn.discordapp.com/attachments/1312378652121501809/1366415346789253161/Screenshot_20250428_195116_Chrome.jpg?ex=6810dcf5&is=680f8b75&hm=1b1db0c122e89a27201c87e16dada889cd00c664f7894977635554a60bc472c0&)

Fractal is a web application that allows users to manage Minecraft server subdomains using Cloudflare's DNS services. Users can authenticate via Discord, create, edit, and delete subdomains, participate in a referral program to earn coins, and purchase additional subdomain slots from a shop. The application includes an admin panel for managing users and their subdomains.

## Features

- **Discord Authentication**: Secure login and registration using Discord OAuth2.
- **Subdomain Management**: Create, edit, and delete subdomains with associated `A` and `SRV` DNS records for Minecraft servers.
- **Cloudflare Integration**: Automatically manages DNS records via Cloudflare's API.
- **Referral Program**: Users can set and share referral codes to earn coins, which can be used in the shop.
- **Shop**: Purchase additional subdomain slots using in-app coins.
- **Admin Panel**: Admins can manage users (suspend/unsuspend), update coins, and delete subdomains.
- **Responsive UI**: Modern, glassmorphism-inspired design with light/dark mode support using Tailwind CSS.
- **Rate Limiting**: Protects against abuse with rate limits on authentication and referral endpoints.
- **Database**: SQLite database for storing user and subdomain data.

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: EJS templates, Tailwind CSS
- **Database**: SQLite3
- **Authentication**: Passport.js with Discord Strategy
- **DNS Management**: Cloudflare API
- **Dependencies**: Axios, dotenv, express-session, express-rate-limit

## Prerequisites

- Node.js (v16 or higher)
- A Cloudflare account with API token
- A Discord application for OAuth2
- A `.env` file with required environment variables

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/fractal.git
   cd fractal
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Set Up Environment Variables**:
   Create a `.env` file in the root directory and add the following:
   ```env
   # Express Session
   SESSION_SECRET=your_session_secret

   # Discord OAuth2
   DISCORD_CLIENT_ID=your_discord_client_id
   DISCORD_CLIENT_SECRET=your_discord_client_secret
   DISCORD_CALLBACK_URL=http://localhost:1027/auth/callback
   DISCORD_LOGIN_CALLBACK_URL=http://localhost:1027/auth/callback
   BOT_TOKEN=your_discord_bot_token

   # Cloudflare
   CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
   DOMAINS=ztx.gd,frac.gg,redstone.sh
   ZONE_IDS=zone_id_1,zone_id_2,zone_id_3

   # Admin Users
   ADMIN_USER_IDS=discord_user_id_1,discord_user_id_2
   ```
   - **SESSION_SECRET**: A random string for session security.
   - **DISCORD_CLIENT_ID/SECRET**: Obtain from your Discord Developer Portal application.
   - **DISCORD_CALLBACK_URL**: The OAuth2 redirect URI (update for production).
   - **BOT_TOKEN**: Token for your Discord bot to add users to a guild.
   - **CLOUDFLARE_API_TOKEN**: Cloudflare API token with `Zone:DNS:Edit` and `Zone:Zone:Read` permissions.
   - **DOMAINS**: List of domains managed by the app.
   - **ZONE_IDS**: Corresponding Cloudflare Zone IDs for each domain.
   - **ADMIN_USER_IDS**: Discord user IDs of admin users.
   - ADMIN_API_KEY=cda35a4dc3f97a53cb1ecba5d17b790a65b315ec // api key for adding coins and subdomain limit to users

4. **Set Up SQLite Database**:
   The application automatically creates a `Frac.db` SQLite database on startup, with tables for `users` and `subdomains`.

5. **Run the Application**:
   ```bash
   npm start
   ```
   The server will run on `http://0.0.0.0:1027`.

## Usage

1. **Login**:
   - Visit `http://localhost:1027` and click "Login with Discord".
   - Authenticate via Discord to access the dashboard.

2. **Dashboard**:
   - View your coins, subdomain count, and available slots.
   - Create, edit, or delete subdomains (e.g., `yourname.ztx.gd`).
   - Participate in the referral program by setting or using a referral code.

3. **Shop**:
   - Purchase additional subdomain slots for 1000 coins.

4. **Admin Panel** (Admins Only):
   - was never implement 

5. **Subdomain Management**:
   - Create a subdomain with an IPv4 address and port for Minecraft servers.
   - Edit existing subdomains to update the name, domain, IP, or port.
   - Delete subdomains to remove them from Cloudflare and the database.

## Project Structure

```
fractal/
├── public/
│   └── images/Frac.png      # Logo image
├── views/
│   ├── login.ejs            # Login page
│   ├── dashboard.ejs        # User dashboard
│   ├── shop.ejs             # Shop page
│   ├── admin.ejs            # Admin panel
│   └── suspended.ejs        # Suspended account page
├── .env                     # Environment variables
├── app.js                   # Main Express application
├── database.js              # SQLite database setup and queries
├── cloudflare.js            # Cloudflare API integration
├── package.json             # Node.js dependencies and scripts
└── README.md                # Project documentation
```

## API Endpoints

- **GET /**: Redirects to login or dashboard.
- **GET /auth/login**: Initiates Discord login.
- **GET /auth/register**: Initiates Discord registration.
- **GET /auth/callback**: Handles Discord OAuth2 callback.
- **GET /auth/logout**: Logs out the user.
- **GET /dashboard**: Displays the user dashboard.
- **GET /shop**: Displays the shop.
- **POST /shop/purchase**: Purchases an item (e.g., subdomain slot).
- **POST /referral/set**: Sets a user’s referral code.
- **POST /referral/use**: Applies a referral code.
- **POST /create_subdomain**: Creates a new subdomain.
- **POST /edit_subdomain**: Edits an existing subdomain.
- **DELETE /delete_subdomain**: Deletes a subdomain.
- **GET /admin**: Displays the admin panel (admin only).
- **POST /admin/update_coins**: Updates a user’s coins (admin only).
- **POST /admin/delete_subdomain**: Deletes a user’s subdomain (admin only).
- **POST /admin/suspend_user**: Suspends a user (admin only).
- **POST /admin/unsuspend_user**: Unsuspends a user (admin only).

## Troubleshooting

- **DNS Records Not Deleting**:
  - Verify `DOMAINS` and `ZONE_IDS` in `.env` match Cloudflare settings.
  - Check Cloudflare API token permissions.
  - Review server logs for errors in `cloudflare.js`.
  - Ensure subdomain and domain inputs are lowercase to avoid case sensitivity issues.

- **Authentication Issues**:
  - Confirm Discord application credentials and callback URLs.
  - Ensure the Discord bot has permissions to add users to the guild.

- **Database Errors**:
  - Check if `Frac.db` is writable in the project directory.
  - Verify SQLite queries in `database.js`.

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.
