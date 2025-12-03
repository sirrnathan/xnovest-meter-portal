require("dotenv").config()
const WebSocket = require('ws');
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')
const express = require("express")
const crypto = require("crypto")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")


// database setup starts here
const createTables = db.transaction( () => {
db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
).run()
})

createTables()

// Add user profile fields to users table
const addUserProfileFields = db.transaction(() => {
    try {
        db.prepare("ALTER TABLE users ADD COLUMN first_name STRING").run();
        db.prepare("ALTER TABLE users ADD COLUMN last_name STRING").run();
        db.prepare("ALTER TABLE users ADD COLUMN phone_number STRING").run();
        db.prepare("ALTER TABLE users ADD COLUMN company STRING").run();
        console.log("User profile fields added successfully");
    } catch (err) {
        // Columns might already exist, ignore error
    }
});

addUserProfileFields();

// Add password reset tokens table
const createPasswordResetTable = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token STRING NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `).run()
})

createPasswordResetTable()

// Add meter tables with 3-phase support
const createMeterTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS meters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name STRING NOT NULL,
            location STRING NOT NULL,
            installation_date DATE NOT NULL,
            capacity_kw REAL NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS meter_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            -- Phase L1
            l1_voltage REAL,
            l1_current REAL,
            l1_power REAL,
            l1_energy REAL,
            
            -- Phase L2
            l2_voltage REAL,
            l2_current REAL,
            l2_power REAL,
            l2_energy REAL,
            
            -- Phase L3
            l3_voltage REAL,
            l3_current REAL,
            l3_power REAL,
            l3_energy REAL,
            
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    `).run()
})

createMeterTables()

// Add is_admin column to users table if it doesn't exist
const addAdminColumn = db.transaction(() => {
    try {
        db.prepare("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE").run();
    } catch (err) {
        // Column might already exist, ignore error
    }
});

addAdminColumn();

// Create admin user if doesn't exist
const createAdminUser = db.transaction(() => {
    const adminCheck = db.prepare("SELECT * FROM users WHERE username = 'admin@xnovest.com'").get();
    if (!adminCheck) {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync("admin123", salt);
        db.prepare("INSERT INTO users (username, password, is_admin, first_name, last_name, phone_number, company) VALUES (?, ?, TRUE, ?, ?, ?, ?)").run(
            "admin@xnovest.com", 
            hashedPassword, 
            "System", 
            "Administrator", 
            "+27 12 345 6789", 
            "Xnovest Africa"
        );
        console.log("Admin user created: admin@xnovest.com / admin123");
    }
});

createAdminUser();

// Helper function to check if user is admin
function isUserAdmin(userId) {
    const userInfo = db.prepare("SELECT is_admin FROM users WHERE id = ?").get(userId);
    return userInfo ? userInfo.is_admin : false;
}

// Helper function to generate reset token
function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Helper function to clean expired tokens
function cleanExpiredTokens() {
    db.prepare("DELETE FROM password_reset_tokens WHERE expires_at < datetime('now') OR used = TRUE").run();
}

// Helper function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Simple in-memory rate limiting
const rateLimitStore = new Map();

function rateLimit(key, limit, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, []);
    }
    
    const requests = rateLimitStore.get(key).filter(time => time > windowStart);
    rateLimitStore.set(key, requests);
    
    if (requests.length >= limit) {
        return false; // Rate limited
    }
    
    requests.push(now);
    return true; // Not rate limited
}

// Clean rate limit store periodically (every hour)
setInterval(() => {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    
    for (const [key, requests] of rateLimitStore.entries()) {
        const filteredRequests = requests.filter(time => time > oneHourAgo);
        if (filteredRequests.length === 0) {
            rateLimitStore.delete(key);
        } else {
            rateLimitStore.set(key, filteredRequests);
        }
    }
}, 60 * 60 * 1000); // Run every hour

// database setup ends here

const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
    res.locals.errors = []

    // try to decode an incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
        
        // Get fresh user data to ensure we have latest profile info
        const userData = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.userid);
        if (userData) {
            // Set display name: first name + last name, or first name, or username as fallback
            if (userData.first_name && userData.last_name) {
                req.user.displayName = `${userData.first_name} ${userData.last_name}`;
            } else if (userData.first_name) {
                req.user.displayName = userData.first_name;
            } else {
                req.user.displayName = userData.username;
            }
            req.user.profileComplete = !!(userData.first_name && userData.last_name);
            req.user.is_admin = userData.is_admin || false;
        }
    } catch(err) {
        req.user = false
    }

    res.locals.user = req.user
    next()
})

// Function to get current phase data for a meter
function getCurrentPhaseData(meterId) {
    // Get the latest reading for this meter
    const latestReading = db.prepare(`
        SELECT * FROM meter_readings 
        WHERE meter_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 1
    `).get(meterId);

    if (latestReading) {
        return {
            l1_voltage: latestReading.l1_voltage || 0,
            l1_current: latestReading.l1_current || 0,
            l1_power: latestReading.l1_power || 0,
            l1_energy: latestReading.l1_energy || 0,
            
            l2_voltage: latestReading.l2_voltage || 0,
            l2_current: latestReading.l2_current || 0,
            l2_power: latestReading.l2_power || 0,
            l2_energy: latestReading.l2_energy || 0,
            
            l3_voltage: latestReading.l3_voltage || 0,
            l3_current: latestReading.l3_current || 0,
            l3_power: latestReading.l3_power || 0,
            l3_energy: latestReading.l3_energy || 0
        };
    }

    // Return default values if no readings exist
    return {
        l1_voltage: 0,
        l1_current: 0,
        l1_power: 0,
        l1_energy: 0,
        
        l2_voltage: 0,
        l2_current: 0,
        l2_power: 0,
        l2_energy: 0,
        
        l3_voltage: 0,
        l3_current: 0,
        l3_power: 0,
        l3_energy: 0
    };
}

app.get("/", (req, res) => {
    if (req.user) {
        return res.redirect("/dashboard");
    }
    res.render("login.ejs");
});

app.get("/dashboard", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    // Check if user is admin
    const isAdmin = isUserAdmin(req.user.userid);

    // Get meters - all meters for admin, user's meters for regular users
    let userMeters = [];
    let selectedMeter = null;
    let meterReadings = [];
    let startDate = "";
    let endDate = "";
    let phaseData = null;
    let allUsers = [];

    // Pagination variables
    const page = parseInt(req.query.page) || 1;
    const limit = 20; // 20 records per page
    const offset = (page - 1) * limit;
    let totalRecords = 0;
    let totalPages = 0;

    if (isAdmin) {
        // Admin can see all meters
        userMeters = db.prepare("SELECT m.*, u.username FROM meters m JOIN users u ON m.user_id = u.id ORDER BY u.username, m.name").all();
        allUsers = db.prepare("SELECT id, username FROM users ORDER BY username").all();
    } else {
        // Regular user only sees their own meters
        userMeters = db.prepare("SELECT * FROM meters WHERE user_id = ? ORDER BY name").all(req.user.userid);
    }

    // Check if a specific meter is requested via query parameter
    const requestedMeterId = req.query.meter_id;
    
    if (userMeters.length > 0) {
        // Find the selected meter
        if (requestedMeterId) {
            selectedMeter = userMeters.find(meter => meter.id == requestedMeterId) || userMeters[0];
        } else {
            selectedMeter = userMeters[0];
        }
        
        // Verify meter access
        if (selectedMeter) {
            if (!isAdmin && selectedMeter.user_id !== req.user.userid) {
                return res.status(403).send("Unauthorized");
            }
            
            // Set date range based on meter installation date
            const installationDate = new Date(selectedMeter.installation_date);
            const today = new Date();
            
            // Default start date: meter installation date or 7 days ago (whichever is more recent)
            let defaultStart = new Date(today);
            defaultStart.setDate(today.getDate() - 7);
            
            // If meter was installed more than 7 days ago, use installation date
            if (installationDate < defaultStart) {
                defaultStart = installationDate;
            }
            
            startDate = req.query.start_date || defaultStart.toISOString().split('T')[0];
            endDate = req.query.end_date || today.toISOString().split('T')[0];
            
            // Get total count for pagination
            const countResult = db.prepare(`
                SELECT COUNT(*) as total 
                FROM meter_readings 
                WHERE meter_id = ? 
                AND date(timestamp) BETWEEN date(?) AND date(?)
            `).get(selectedMeter.id, startDate, endDate);
            
            totalRecords = countResult ? countResult.total : 0;
            totalPages = Math.ceil(totalRecords / limit);
            
            // Get meter readings ONLY for the selected meter with pagination
            meterReadings = db.prepare(`
                SELECT * FROM meter_readings 
                WHERE meter_id = ? 
                AND date(timestamp) BETWEEN date(?) AND date(?)
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            `).all(selectedMeter.id, startDate, endDate, limit, offset);
            
            // Get current phase data for the selected meter
            phaseData = getCurrentPhaseData(selectedMeter.id);
        }
    }

    res.render("dashboard.ejs", {
        userMeters: userMeters,
        selectedMeter: selectedMeter,
        meterReadings: meterReadings,
        startDate: startDate,
        endDate: endDate,
        phaseData: phaseData,
        isAdmin: isAdmin,
        allUsers: allUsers,
        // Pagination data
        currentPage: page,
        totalPages: totalPages,
        totalRecords: totalRecords,
        limit: limit
    });
});

app.get("/login", (req, res) => {
    res.render("login.ejs")
})

// Forgot Password - Show form
app.get("/forgot-password", (req, res) => {
    if (req.user) {
        return res.redirect("/dashboard");
    }
    res.render("forgot-password.ejs");
});

// Forgot Password - Process request (SECURE VERSION)
app.post("/forgot-password", (req, res) => {
    const errors = [];
    const { username } = req.body;

    if (!username) {
        errors.push("Please enter your email address");
        return res.render("forgot-password.ejs", { errors });
    }

    // Validate email format
    if (!isValidEmail(username)) {
        errors.push("Please enter a valid email address");
        return res.render("forgot-password.ejs", { errors });
    }

    // Rate limiting: max 3 requests per 15 minutes per IP
    const ip = req.ip || req.connection.remoteAddress;
    if (!rateLimit(`forgot-password:${ip}`, 3, 15 * 60 * 1000)) {
        // Still show success message to avoid revealing information
        return res.render("forgot-password-success.ejs", { 
            message: "If an account with that email exists, a password reset link has been sent."
        });
    }

    // Clean expired tokens first
    cleanExpiredTokens();

    // Check if user exists - but don't reveal if they do or don't
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    
    if (user) {
        // Rate limiting per user: max 2 requests per hour per user
        if (!rateLimit(`forgot-password-user:${user.id}`, 2, 60 * 60 * 1000)) {
            // Still show success message to avoid revealing user existence
            return res.render("forgot-password-success.ejs", { 
                message: "If an account with that email exists, a password reset link has been sent."
            });
        }

        // User exists - generate reset token
        const resetToken = generateResetToken();
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

        // Save token to database
        try {
            db.prepare(`
                INSERT INTO password_reset_tokens (user_id, token, expires_at) 
                VALUES (?, ?, ?)
            `).run(user.id, resetToken, expiresAt.toISOString());

            // In production, this is where you would send the email
            // For now, we'll log it to console for testing
            const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
            console.log(`[SECURITY] Password reset link generated for ${user.username}: ${resetLink}`);
            
        } catch (error) {
            console.error("Error creating reset token:", error);
            // Don't reveal the error to the user - fall through to success message
        }
    }

    // ALWAYS show the same success message regardless of whether user exists or not
    // This prevents email enumeration attacks
    res.render("forgot-password-success.ejs", { 
        message: "If an account with that email exists, a password reset link has been sent."
    });
});

// Reset Password - Show form
app.get("/reset-password", (req, res) => {
    if (req.user) {
        return res.redirect("/dashboard");
    }

    const { token } = req.query;
    
    if (!token) {
        return res.render("reset-password-error.ejs", { 
            message: "Invalid or missing reset token." 
        });
    }

    // Clean expired tokens
    cleanExpiredTokens();

    // Verify token
    const tokenRecord = db.prepare(`
        SELECT pt.*, u.username 
        FROM password_reset_tokens pt 
        JOIN users u ON pt.user_id = u.id 
        WHERE pt.token = ? AND pt.used = FALSE AND pt.expires_at > datetime('now')
    `).get(token);

    if (!tokenRecord) {
        return res.render("reset-password-error.ejs", { 
            message: "Invalid or expired reset token. Please request a new password reset." 
        });
    }

    res.render("reset-password.ejs", { 
        token: token,
        username: tokenRecord.username 
    });
});

// Reset Password - Process new password
app.post("/reset-password", (req, res) => {
    const errors = [];
    const { token, password, confirm_password } = req.body;

    if (!token) {
        return res.render("reset-password-error.ejs", { 
            message: "Invalid reset token." 
        });
    }

    if (!password || password.length < 12) {
        errors.push("Password must be at least 12 characters long.");
    }

    if (password !== confirm_password) {
        errors.push("Passwords do not match.");
    }

    if (errors.length > 0) {
        const tokenRecord = db.prepare(`
            SELECT u.username 
            FROM password_reset_tokens pt 
            JOIN users u ON pt.user_id = u.id 
            WHERE pt.token = ? AND pt.used = FALSE AND pt.expires_at > datetime('now')
        `).get(token);

        if (!tokenRecord) {
            return res.render("reset-password-error.ejs", { 
                message: "Invalid or expired reset token." 
            });
        }

        return res.render("reset-password.ejs", { 
            token: token,
            username: tokenRecord.username,
            errors: errors
        });
    }

    // Clean expired tokens
    cleanExpiredTokens();

    // Verify token and get user
    const tokenRecord = db.prepare(`
        SELECT pt.*, u.id as user_id 
        FROM password_reset_tokens pt 
        JOIN users u ON pt.user_id = u.id 
        WHERE pt.token = ? AND pt.used = FALSE AND pt.expires_at > datetime('now')
    `).get(token);

    if (!tokenRecord) {
        return res.render("reset-password-error.ejs", { 
            message: "Invalid or expired reset token. Please request a new password reset." 
        });
    }

    // Update user password
    try {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        // Update user password
        db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, tokenRecord.user_id);
        
        // Mark token as used
        db.prepare("UPDATE password_reset_tokens SET used = TRUE WHERE token = ?").run(token);

        console.log(`[SECURITY] Password successfully reset for user ID: ${tokenRecord.user_id}`);

        res.render("reset-password-success.ejs");
    } catch (error) {
        console.error("Error resetting password:", error);
        errors.push("An error occurred while resetting your password. Please try again.");
        
        const tokenRecord = db.prepare(`
            SELECT u.username 
            FROM password_reset_tokens pt 
            JOIN users u ON pt.user_id = u.id 
            WHERE pt.token = ? AND pt.used = FALSE AND pt.expires_at > datetime('now')
        `).get(token);

        return res.render("reset-password.ejs", { 
            token: token,
            username: tokenRecord.username,
            errors: errors
        });
    }
});

// Change Password - For logged-in users
app.get("/change-password", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    res.render("change-password.ejs");
});

app.post("/change-password", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const errors = [];
    const { current_password, new_password, confirm_password } = req.body;

    // Get current user
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userid);

    if (!user) {
        errors.push("User not found.");
        return res.render("change-password.ejs", { errors });
    }

    // Verify current password
    const matchOrNot = bcrypt.compareSync(current_password, user.password);
    if (!matchOrNot) {
        errors.push("Current password is incorrect.");
    }

    if (!new_password || new_password.length < 12) {
        errors.push("New password must be at least 12 characters long.");
    }

    if (new_password !== confirm_password) {
        errors.push("New passwords do not match.");
    }

    if (errors.length > 0) {
        return res.render("change-password.ejs", { errors });
    }

    // Update password
    try {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(new_password, salt);

        db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, user.id);

        console.log(`[SECURITY] Password successfully changed for user: ${user.username}`);

        res.render("change-password-success.ejs");
    } catch (error) {
        console.error("Error changing password:", error);
        errors.push("An error occurred while changing your password. Please try again.");
        return res.render("change-password.ejs", { errors });
    }
});

// User Profile Routes
app.get("/profile", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    // Get current user data with proper error handling
    const userData = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userid);
    
    if (!userData) {
        return res.redirect("/login");
    }
    
    res.render("profile.ejs", {
        user: userData,
        errors: []
    });
});

app.post("/update-profile", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const errors = [];
    const { first_name, last_name, phone_number, company } = req.body;

    // Validation
    if (!first_name || first_name.trim() === '') {
        errors.push("First name is required");
    }
    if (!last_name || last_name.trim() === '') {
        errors.push("Last name is required");
    }
    if (first_name && first_name.length > 50) {
        errors.push("First name cannot exceed 50 characters");
    }
    if (last_name && last_name.length > 50) {
        errors.push("Last name cannot exceed 50 characters");
    }
    if (phone_number && phone_number.length > 20) {
        errors.push("Phone number cannot exceed 20 characters");
    }
    if (company && company.length > 100) {
        errors.push("Company name cannot exceed 100 characters");
    }

    if (errors.length > 0) {
        const userData = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userid);
        return res.render("profile.ejs", {
            user: userData,
            errors: errors
        });
    }

    // Update user profile
    try {
        db.prepare(`
            UPDATE users 
            SET first_name = ?, last_name = ?, phone_number = ?, company = ?
            WHERE id = ?
        `).run(
            first_name.trim(),
            last_name.trim(),
            phone_number ? phone_number.trim() : null,
            company ? company.trim() : null,
            req.user.userid
        );

        console.log(`Profile updated for user: ${req.user.username}`);
        
        // Update the JWT token with new name for immediate display
        const updatedUser = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userid);
        
        // Set display name: first name + last name, or first name, or username as fallback
        let displayName;
        if (updatedUser.first_name && updatedUser.last_name) {
            displayName = `${updatedUser.first_name} ${updatedUser.last_name}`;
        } else if (updatedUser.first_name) {
            displayName = updatedUser.first_name;
        } else {
            displayName = updatedUser.username;
        }
        
        const ourTokenValue = jwt.sign(
            {
                exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, 
                skyColor: "blue", 
                userid: updatedUser.id, 
                username: updatedUser.username, 
                displayName: displayName
            }, 
            process.env.JWTSECRET
        );

        res.cookie("ourSimpleApp", ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24
        });

        res.redirect("/dashboard?profile_updated=true");
    } catch (error) {
        console.error("Error updating profile:", error);
        errors.push("An error occurred while updating your profile. Please try again.");
        const userData = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userid);
        return res.render("profile.ejs", {
            user: userData,
            errors: errors
        });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/login")
})

app.get("/register", (req, res) => {
    if (req.user) {
        return res.redirect("/dashboard");
    }
    res.render("homepage.ejs");
});

app.post("/login", (req, res) => {
    let errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.username = ""

    if (req.body.username.trim() == "") errors = ["Invalid email address or password."]
    if (req.body.password == "") errors = ["Invalid email address or password."]

    if (errors.length) {
        return res.render("login.ejs", {errors})
    }

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if (!userInQuestion) {
        errors = ["Invalid email address / password."]
        return res.render("login.ejs", {errors})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot){
        errors = ["Invalid email address / password."]
        return res.render("login.ejs", {errors})
    }

    // Set display name: first name + last name, or first name, or username as fallback
    let displayName;
    if (userInQuestion.first_name && userInQuestion.last_name) {
        displayName = `${userInQuestion.first_name} ${userInQuestion.last_name}`;
    } else if (userInQuestion.first_name) {
        displayName = userInQuestion.first_name;
    } else {
        displayName = userInQuestion.username;
    }

    const ourTokenValue = jwt.sign(
        {
            exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, 
            skyColor: "blue", 
            userid: userInQuestion.id, 
            username: userInQuestion.username, 
            displayName: displayName
        }, 
        process.env.JWTSECRET
    );

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/dashboard")
})

// Update registration to include profile fields
app.post("/register", (req, res) => {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.username = ""
    if (typeof req.body.first_name !== "string") req.body.first_name = ""
    if (typeof req.body.last_name !== "string") req.body.last_name = ""

    req.body.username = req.body.username.trim().toLowerCase() // Convert to lowercase
    req.body.first_name = req.body.first_name.trim()
    req.body.last_name = req.body.last_name.trim()

    if (!req.body.username) errors.push("You must provide an email address.")
    
    // Email validation
    if (req.body.username && !isValidEmail(req.body.username)) {
        errors.push("Please enter a valid email address.")
    }
    
    if (req.body.username && req.body.username.length > 100) errors.push("Email address cannot exceed 100 characters.")

    // Name validation
    if (!req.body.first_name) errors.push("First name is required.")
    if (!req.body.last_name) errors.push("Last name is required.")
    if (req.body.first_name && req.body.first_name.length > 50) errors.push("First name cannot exceed 50 characters.")
    if (req.body.last_name && req.body.last_name.length > 50) errors.push("Last name cannot exceed 50 characters.")

    //CHECK IF EMAIL EXISTS ALREADY
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    if (!req.body.password) errors.push("You must provide a password.")
    if (req.body.password && req.body.password.length < 12) errors.push("Password must be at least 12 characters.")
    if (req.body.password && req.body.password.length > 70) errors.push("Password cannot exceed 70 characters.")

    if (usernameCheck) errors.push("An account with that email address already exists.")

    if (errors.length) {
        return res.render("homepage.ejs", {errors})
    } 

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password, first_name, last_name) VALUES (?, ?, ?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password, req.body.first_name, req.body.last_name)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // Set display name: first name + last name, or first name, or username as fallback
    let displayName;
    if (ourUser.first_name && ourUser.last_name) {
        displayName = `${ourUser.first_name} ${ourUser.last_name}`;
    } else if (ourUser.first_name) {
        displayName = ourUser.first_name;
    } else {
        displayName = ourUser.username;
    }

    // log a user in by giving them a cookie
    const ourTokenValue = jwt.sign(
        {
            exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, 
            skyColor: "blue", 
            userid: ourUser.id, 
            username: ourUser.username, 
            displayName: displayName
        }, 
        process.env.JWTSECRET
    );

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/dashboard")
})

// Add new meter - ADMIN ONLY
app.post("/add-meter", (req, res) => {
    if (!req.user) {
        return res.redirect("/login")
    }

    // Only admin can add meters
    if (!isUserAdmin(req.user.userid)) {
        return res.status(403).send("Unauthorized - Admin access required");
    }

    const errors = []
    const { name, location, installation_date, capacity_kw, user_id } = req.body

    // Validation
    if (!name) errors.push("Meter name is required")
    if (!location) errors.push("Location is required")
    if (!installation_date) errors.push("Installation date is required")
    if (!capacity_kw || capacity_kw <= 0) errors.push("Valid capacity is required")
    if (!user_id) errors.push("User selection is required")

    if (errors.length) {
        const userMeters = db.prepare("SELECT m.*, u.username FROM meters m JOIN users u ON m.user_id = u.id ORDER BY u.username, m.name").all();
        const allUsers = db.prepare("SELECT id, username FROM users ORDER BY username").all();
        
        return res.render("dashboard.ejs", {
            userMeters: userMeters,
            selectedMeter: null,
            meterReadings: [],
            errors: errors,
            isAdmin: true,
            allUsers: allUsers
        })
    }

    // Verify the target user exists
    const targetUser = db.prepare("SELECT * FROM users WHERE id = ?").get(user_id);
    if (!targetUser) {
        return res.status(400).send("Invalid user selected");
    }

    // Insert new meter for the selected user
    const result = db.prepare(`
        INSERT INTO meters (user_id, name, location, installation_date, capacity_kw) 
        VALUES (?, ?, ?, ?, ?)
    `).run(user_id, name, location, installation_date, parseFloat(capacity_kw))

    res.redirect("/dashboard")
})

// Delete meter - ADMIN ONLY
app.post("/delete-meter", (req, res) => {
    if (!req.user) {
        return res.redirect("/login")
    }

    // Only admin can delete meters
    if (!isUserAdmin(req.user.userid)) {
        return res.status(403).send("Unauthorized - Admin access required");
    }

    const { meter_id } = req.body

    // Verify meter exists
    const meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(meter_id);
    if (!meter) {
        return res.status(404).send("Meter not found");
    }

    // Delete meter readings first (foreign key constraint)
    db.prepare("DELETE FROM meter_readings WHERE meter_id = ?").run(meter_id)
    
    // Delete meter
    db.prepare("DELETE FROM meters WHERE id = ?").run(meter_id)

    res.redirect("/dashboard")
})

// Filter meter data - CHANGED FROM POST TO GET
app.get("/filter-meter-data", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const { meter_id, start_date, end_date, page = 1 } = req.query;

    // Check if user is admin
    const isAdmin = isUserAdmin(req.user.userid);

    // Verify meter access - admin can access any meter, regular users only their own
    let selectedMeter;
    if (isAdmin) {
        selectedMeter = db.prepare("SELECT * FROM meters WHERE id = ?").get(meter_id);
    } else {
        selectedMeter = db.prepare("SELECT * FROM meters WHERE id = ? AND user_id = ?").get(meter_id, req.user.userid);
    }
    
    if (!selectedMeter) {
        return res.status(403).send("Unauthorized");
    }

    // Get meters - all meters for admin, user's meters for regular users
    let userMeters = [];
    let allUsers = [];

    if (isAdmin) {
        userMeters = db.prepare("SELECT m.*, u.username FROM meters m JOIN users u ON m.user_id = u.id ORDER BY u.username, m.name").all();
        allUsers = db.prepare("SELECT id, username FROM users ORDER BY username").all();
    } else {
        userMeters = db.prepare("SELECT * FROM meters WHERE user_id = ? ORDER BY name").all(req.user.userid);
    }
    
    // Pagination variables
    const currentPage = parseInt(page) || 1;
    const limit = 20;
    const offset = (currentPage - 1) * limit;
    let totalRecords = 0;
    let totalPages = 0;
    
    let meterReadings = [];
    if (start_date && end_date) {
        // Get total count for pagination
        const countResult = db.prepare(`
            SELECT COUNT(*) as total 
            FROM meter_readings 
            WHERE meter_id = ? 
            AND date(timestamp) BETWEEN date(?) AND date(?)
        `).get(meter_id, start_date, end_date);
        
        totalRecords = countResult ? countResult.total : 0;
        totalPages = Math.ceil(totalRecords / limit);
        
        // Get readings ONLY for the selected meter with pagination
        meterReadings = db.prepare(`
            SELECT * FROM meter_readings 
            WHERE meter_id = ? 
            AND date(timestamp) BETWEEN date(?) AND date(?)
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        `).all(meter_id, start_date, end_date, limit, offset);
    }

    // Get current phase data for the selected meter
    const phaseData = getCurrentPhaseData(meter_id);

    res.render("dashboard.ejs", {
        userMeters: userMeters,
        selectedMeter: selectedMeter,
        meterReadings: meterReadings,
        startDate: start_date,
        endDate: end_date,
        phaseData: phaseData,
        isAdmin: isAdmin,
        allUsers: allUsers,
        // Pagination data
        currentPage: currentPage,
        totalPages: totalPages,
        totalRecords: totalRecords,
        limit: limit
    });
})

// Generate sample data for a meter - ADMIN ONLY (HOURLY READINGS AT EXACT INTERVALS)
app.post("/generate-sample-data", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    // Only admin can generate sample data
    if (!isUserAdmin(req.user.userid)) {
        return res.status(403).send("Unauthorized - Admin access required");
    }

    const { meter_id } = req.body;

    // Verify meter exists
    const meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(meter_id);
    if (!meter) {
        return res.status(404).send("Meter not found");
    }

    // First, delete any existing data for this meter to avoid duplicates
    db.prepare("DELETE FROM meter_readings WHERE meter_id = ?").run(meter_id);

    // Generate sample data from installation date to today
    const installationDate = new Date(meter.installation_date);
    const today = new Date();
    
    // Set installation date to start of day (00:00:00)
    installationDate.setHours(0, 0, 0, 0);
    
    // Set today to end of day (23:59:59)
    today.setHours(23, 59, 59, 999);
    
    // Calculate total hours between installation and today
    const totalMs = today - installationDate;
    const totalHours = Math.floor(totalMs / (1000 * 60 * 60));
    
    // Create VERY different data patterns based on meter ID
    const meterPattern = parseInt(meter_id) % 4; // 4 different patterns
    
    console.log(`Generating ${totalHours} hours of sample data (exact 1-hour intervals) for meter ${meter_id} (Pattern: ${meterPattern})`);
    console.log(`Installation date: ${installationDate.toISOString()}`);
    console.log(`End date: ${today.toISOString()}`);
    
    // Use a transaction for better performance
    const insertReading = db.prepare(`
        INSERT INTO meter_readings 
        (meter_id, timestamp, l1_voltage, l1_current, l1_power, l1_energy, 
         l2_voltage, l2_current, l2_power, l2_energy,
         l3_voltage, l3_current, l3_power, l3_energy) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const generateData = db.transaction(() => {
        // Generate readings at exact 1-hour intervals
        for (let hour = 0; hour <= totalHours; hour++) {
            const timestamp = new Date(installationDate.getTime() + (hour * 60 * 60 * 1000));
            
            // Ensure exact hour boundaries (00 minutes, 00 seconds, 000 milliseconds)
            timestamp.setMinutes(0, 0, 0);

            // Generate completely different data based on meter pattern
            let baseVoltage, baseCurrent, basePower, energyIncrement;
            
            switch(meterPattern) {
                case 0: // High consumption pattern (Industrial - runs 24/7)
                    baseVoltage = 235;
                    baseCurrent = 25;
                    basePower = 5.8;
                    energyIncrement = 5.0; // High hourly consumption
                    break;
                case 1: // Medium consumption pattern (Commercial - business hours)
                    baseVoltage = 230;
                    baseCurrent = 15;
                    basePower = 3.4;
                    energyIncrement = 3.1; // Medium hourly consumption
                    break;
                case 2: // Low consumption pattern (Residential - peaks in evening)
                    baseVoltage = 225;
                    baseCurrent = 8;
                    basePower = 1.8;
                    energyIncrement = 1.5; // Low hourly consumption
                    break;
                case 3: // Variable consumption pattern (Mixed use - varies by time)
                    baseVoltage = 228;
                    baseCurrent = 18;
                    basePower = 4.1;
                    energyIncrement = 3.8; // Variable hourly consumption
                    break;
            }
            
            // Add time-of-day variation (higher during day, lower at night)
            const currentHour = timestamp.getHours();
            let timeOfDayFactor;
            if (currentHour >= 6 && currentHour <= 18) { // Daytime (6 AM - 6 PM)
                timeOfDayFactor = 1.0;
            } else if (currentHour >= 19 && currentHour <= 22) { // Evening (7 PM - 10 PM)
                timeOfDayFactor = meterPattern === 2 ? 1.4 : 0.8; // Residential peaks in evening
            } else { // Night (11 PM - 5 AM)
                timeOfDayFactor = 0.3;
            }
            
            // Add weekday/weekend variation
            const dayOfWeek = timestamp.getDay(); // 0 = Sunday, 6 = Saturday
            const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
            const dayFactor = isWeekend ? 0.7 : 1.0;
            
            // Add some randomness but keep the pattern distinct
            const randomFactor = 0.9 + (Math.random() * 0.2); // 0.9 to 1.1
            
            // Calculate final values with all factors
            const finalFactor = timeOfDayFactor * dayFactor * randomFactor;
            
            // Calculate energy as cumulative value
            const baseEnergy = 50 + (energyIncrement * hour);
            
            const l1_voltage = baseVoltage + (Math.random() * 10 - 5);
            const l1_current = baseCurrent * finalFactor + (Math.random() * 4 - 2);
            const l1_power = basePower * finalFactor + (Math.random() * 1 - 0.5);
            const l1_energy = baseEnergy + (Math.random() * 20 - 10);
            
            const l2_voltage = baseVoltage - 2 + (Math.random() * 10 - 5);
            const l2_current = (baseCurrent - 1) * finalFactor + (Math.random() * 4 - 2);
            const l2_power = (basePower - 0.3) * finalFactor + (Math.random() * 1 - 0.5);
            const l2_energy = baseEnergy + 25 + (Math.random() * 20 - 10);
            
            const l3_voltage = baseVoltage + 3 + (Math.random() * 10 - 5);
            const l3_current = (baseCurrent + 0.5) * finalFactor + (Math.random() * 4 - 2);
            const l3_power = (basePower + 0.2) * finalFactor + (Math.random() * 1 - 0.5);
            const l3_energy = baseEnergy - 20 + (Math.random() * 20 - 10);

            insertReading.run(
                meter_id,
                timestamp.toISOString(), // Use ISO string for consistent UTC storage
                parseFloat(l1_voltage.toFixed(2)),
                parseFloat(l1_current.toFixed(2)),
                parseFloat(l1_power.toFixed(2)),
                parseFloat(l1_energy.toFixed(2)),
                parseFloat(l2_voltage.toFixed(2)),
                parseFloat(l2_current.toFixed(2)),
                parseFloat(l2_power.toFixed(2)),
                parseFloat(l2_energy.toFixed(2)),
                parseFloat(l3_voltage.toFixed(2)),
                parseFloat(l3_current.toFixed(2)),
                parseFloat(l3_power.toFixed(2)),
                parseFloat(l3_energy.toFixed(2))
            );
        }
    });

    try {
        generateData();
        console.log(`Successfully generated ${totalHours} hourly readings at exact 1-hour intervals for meter ${meter_id}`);
        res.redirect("/dashboard?meter_id=" + meter_id + "&data_generated=true");
    } catch (error) {
        console.error("Error generating sample data:", error);
        res.status(500).send("Error generating sample data");
    }
});

// Add this route to serve chart data
app.get("/chart-data", (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: "Not authenticated" });
    }

    const { meter_id, days = 7 } = req.query;

    // Check if user is admin
    const isAdmin = isUserAdmin(req.user.userid);

    // Verify meter access
    let meter;
    if (isAdmin) {
        meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(meter_id);
    } else {
        meter = db.prepare("SELECT * FROM meters WHERE id = ? AND user_id = ?").get(meter_id, req.user.userid);
    }

    if (!meter) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Get meter readings for the chart
    const readings = db.prepare(`
        SELECT 
            timestamp,
            COALESCE(l1_energy, 0) as l1_energy,
            COALESCE(l2_energy, 0) as l2_energy, 
            COALESCE(l3_energy, 0) as l3_energy,
            COALESCE(l1_energy, 0) + COALESCE(l2_energy, 0) + COALESCE(l3_energy, 0) as total_energy
        FROM meter_readings 
        WHERE meter_id = ? 
        AND timestamp BETWEEN ? AND ?
        ORDER BY timestamp
    `).all(meter_id, startDate.toISOString(), endDate.toISOString());

    // If no readings, return empty data with proper structure
    if (readings.length === 0) {
        const emptyChartData = {
            labels: [],
            datasets: [
                {
                    label: 'L1 Energy (kWh)',
                    data: [],
                    borderColor: '#ff6384',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                },
                {
                    label: 'L2 Energy (kWh)',
                    data: [],
                    borderColor: '#36a2eb',
                    backgroundColor: 'rgba(54, 162, 235, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                },
                {
                    label: 'L3 Energy (kWh)',
                    data: [],
                    borderColor: '#ffce56',
                    backgroundColor: 'rgba(255, 206, 86, 0.1)',
                    tension: 0.4,
                    borderWidth: 2
                },
                {
                    label: 'Total Energy (kWh)',
                    data: [],
                    borderColor: '#4bc0c0',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    borderWidth: 3,
                    tension: 0.4
                }
            ]
        };
        return res.json(emptyChartData);
    }

    // Format data for chart
    const chartData = {
        labels: readings.map(r => {
            const date = new Date(r.timestamp);
            if (parseInt(days) <= 1) {
                // For 1 day, show time in HH:MM format
                return date.toLocaleTimeString('en-US', { 
                    hour: '2-digit', 
                    minute: '2-digit',
                    hour12: false 
                });
            } else if (parseInt(days) <= 7) {
                // For 1 week, show day and time
                return date.toLocaleDateString('en-US', { 
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    hour12: false
                });
            } else {
                // For longer periods, show date only
                return date.toLocaleDateString();
            }
        }),
        datasets: [
            {
                label: 'L1 Energy (kWh)',
                data: readings.map(r => r.l1_energy),
                borderColor: '#ff6384',
                backgroundColor: 'rgba(255, 99, 132, 0.1)',
                tension: 0.4,
                borderWidth: 2
            },
            {
                label: 'L2 Energy (kWh)',
                data: readings.map(r => r.l2_energy),
                borderColor: '#36a2eb',
                backgroundColor: 'rgba(54, 162, 235, 0.1)',
                tension: 0.4,
                borderWidth: 2
            },
            {
                label: 'L3 Energy (kWh)',
                data: readings.map(r => r.l3_energy),
                borderColor: '#ffce56',
                backgroundColor: 'rgba(255, 206, 86, 0.1)',
                tension: 0.4,
                borderWidth: 2
            },
            {
                label: 'Total Energy (kWh)',
                data: readings.map(r => r.total_energy),
                borderColor: '#4bc0c0',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                borderWidth: 3,
                tension: 0.4
            }
        ]
    };

    res.json(chartData);
});

// Download CSV
app.get("/download-csv", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const { meter_id, start_date, end_date } = req.query;

    // Check if user is admin
    const isAdmin = isUserAdmin(req.user.userid);

    // Verify meter access - admin can access any meter, regular users only their own
    let meter;
    if (isAdmin) {
        meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(meter_id);
    } else {
        meter = db.prepare("SELECT * FROM meters WHERE id = ? AND user_id = ?").get(meter_id, req.user.userid);
    }
    
    if (!meter) {
        return res.status(403).send("Unauthorized");
    }

    // Get readings ONLY for the selected meter
    const meterReadings = db.prepare(`
        SELECT * FROM meter_readings 
        WHERE meter_id = ? 
        AND date(timestamp) BETWEEN date(?) AND date(?)
        ORDER BY timestamp
    `).all(meter_id, start_date, end_date);

    if (meterReadings.length === 0) {
        return res.status(404).send("No data found for the selected criteria");
    }

    // Generate CSV
    let csv = 'Timestamp,'
    csv += 'L1_Voltage (V),L1_Current (A),L1_Power (kW),L1_Energy (kWh),'
    csv += 'L2_Voltage (V),L2_Current (A),L2_Power (kW),L2_Energy (kWh),'
    csv += 'L3_Voltage (V),L3_Current (A),L3_Power (kW),L3_Energy (kWh)\n'
    
    meterReadings.forEach(row => {
        const timestamp = new Date(row.timestamp).toLocaleString()
        csv += `"${timestamp}",${row.l1_voltage || 0},${row.l1_current || 0},${row.l1_power || 0},${row.l1_energy || 0},`
        csv += `${row.l2_voltage || 0},${row.l2_current || 0},${row.l2_power || 0},${row.l2_energy || 0},`
        csv += `${row.l3_voltage || 0},${row.l3_current || 0},${row.l3_power || 0},${row.l3_energy || 0}\n`
    })

    const filename = `meter_data_${meter.name}_${start_date}_to_${end_date}.csv`
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
    res.send(csv)
})

// Debug route to check meter data
app.get("/debug-meter-data", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const userMeters = db.prepare("SELECT * FROM meters WHERE user_id = ?").all(req.user.userid);
    
    const meterData = userMeters.map(meter => {
        const readings = db.prepare("SELECT COUNT(*) as count FROM meter_readings WHERE meter_id = ?").get(meter.id);
        const latest = db.prepare("SELECT * FROM meter_readings WHERE meter_id = ? ORDER BY timestamp DESC LIMIT 1").get(meter.id);
        
        return {
            meter: meter,
            readingCount: readings.count,
            latestReading: latest
        };
    });

    res.json({
        user: req.user.username,
        meters: meterData
    });
});

// Debug route to check timestamp intervals
app.get("/debug-intervals", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const { meter_id } = req.query;
    
    const readings = db.prepare(`
        SELECT timestamp 
        FROM meter_readings 
        WHERE meter_id = ? 
        ORDER BY timestamp 
        LIMIT 100
    `).all(meter_id);

    const intervals = [];
    for (let i = 1; i < readings.length; i++) {
        const prev = new Date(readings[i-1].timestamp);
        const curr = new Date(readings[i].timestamp);
        const diffMs = curr - prev;
        const diffHours = diffMs / (1000 * 60 * 60);
        intervals.push({
            from: readings[i-1].timestamp,
            to: readings[i].timestamp,
            diff_hours: diffHours
        });
    }

    res.json({
        total_readings: readings.length,
        intervals: intervals
    });
});

app.listen(3000, () => {
    console.log("Server running on port 3000")
})