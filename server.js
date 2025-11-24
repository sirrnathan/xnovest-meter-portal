require("dotenv").config()
const WebSocket = require('ws');
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')
const express = require("express")
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
    const adminCheck = db.prepare("SELECT * FROM users WHERE username = 'admin'").get();
    if (!adminCheck) {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync("admin123", salt);
        db.prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, TRUE)").run("admin", hashedPassword);
        console.log("Admin user created: admin / admin123");
    }
});

createAdminUser();

// Helper function to check if user is admin
function isUserAdmin(userId) {
    const userInfo = db.prepare("SELECT is_admin FROM users WHERE id = ?").get(userId);
    return userInfo ? userInfo.is_admin : false;
}

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
    } catch(err) {
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)

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
            l1_voltage: latestReading.l1_voltage,
            l1_current: latestReading.l1_current,
            l1_power: latestReading.l1_power,
            l1_energy: latestReading.l1_energy,
            
            l2_voltage: latestReading.l2_voltage,
            l2_current: latestReading.l2_current,
            l2_power: latestReading.l2_power,
            l2_energy: latestReading.l2_energy,
            
            l3_voltage: latestReading.l3_voltage,
            l3_current: latestReading.l3_current,
            l3_power: latestReading.l3_power,
            l3_energy: latestReading.l3_energy
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

// Function to get meter installation date
function getMeterInstallationDate(meterId) {
    const meter = db.prepare("SELECT installation_date FROM meters WHERE id = ?").get(meterId);
    return meter ? meter.installation_date : null;
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
        }
        
        // Set date range based on meter installation date
        if (selectedMeter) {
            const installationDate = new Date(selectedMeter.installation_date);
            const today = new Date();
            
            // Default start date: meter installation date or 7 days ago (whichever is more recent)
            let defaultStart = new Date(today);
            defaultStart.setDate(today.getDate() - 7);
            
            // If meter was installed more than 7 days ago, use installation date
            if (installationDate < defaultStart) {
                defaultStart = installationDate;
            }
            
            startDate = defaultStart.toISOString().split('T')[0];
            endDate = today.toISOString().split('T')[0];
            
            // Get meter readings ONLY for the selected meter
            meterReadings = db.prepare(`
                SELECT * FROM meter_readings 
                WHERE meter_id = ? 
                AND date(timestamp) BETWEEN date(?) AND date(?)
                ORDER BY timestamp DESC
            `).all(selectedMeter.id, startDate, endDate);
            
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
        allUsers: allUsers
    });
});

app.get("/login", (req, res) => {
    res.render("login.ejs")
})

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

    if (req.body.username.trim() == "") errors = ["Invalid username or password."]
    if (req.body.password == "") errors = ["Invalid username or password."]

    if (errors.length) {
        return res.render("login.ejs", {errors})
    }

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if (!userInQuestion) {
        errors = ["Invalid username / password."]
        return res.render("login.ejs", {errors})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot){
        errors = ["Invalid username / password."]
        return res.render("login.ejs", {errors})
    }

    const ourTokenValue = jwt.sign(
        {exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username}, 
        process.env.JWTSECRET
    )

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

// Filter meter data
app.post("/filter-meter-data", (req, res) => {
    if (!req.user) {
        return res.redirect("/login");
    }

    const { meter_id, start_date, end_date } = req.body;

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
    
    let meterReadings = [];
    if (start_date && end_date) {
        // Get readings ONLY for the selected meter
        meterReadings = db.prepare(`
            SELECT * FROM meter_readings 
            WHERE meter_id = ? 
            AND date(timestamp) BETWEEN date(?) AND date(?)
            ORDER BY timestamp DESC
        `).all(meter_id, start_date, end_date);
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
        allUsers: allUsers
    });
})

// Generate sample data for a meter - ADMIN ONLY
// Generate sample data for a meter - ADMIN ONLY
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
    
    // Calculate total days between installation and today
    const totalDays = Math.floor((today - installationDate) / (1000 * 60 * 60 * 24));
    
    // Create VERY different data patterns based on meter ID
    const meterPattern = parseInt(meter_id) % 4; // 4 different patterns
    
    // Generate multiple readings per day (to simulate real data)
    const readingsPerDay = 24; // One reading per hour
    
    for (let day = 0; day <= totalDays; day++) {
        const currentDate = new Date(installationDate);
        currentDate.setDate(currentDate.getDate() + day);
        
        for (let hour = 0; hour < 24; hour += Math.floor(24 / readingsPerDay)) {
            const timestamp = new Date(currentDate);
            timestamp.setHours(hour);
            timestamp.setMinutes(Math.floor(Math.random() * 60));
            timestamp.setSeconds(Math.floor(Math.random() * 60));
            
            // Generate completely different data based on meter pattern
            let baseVoltage, baseCurrent, basePower, energyIncrement;
            
            switch(meterPattern) {
                case 0: // High consumption pattern
                    baseVoltage = 235;
                    baseCurrent = 18;
                    basePower = 4.2;
                    energyIncrement = 3.5;
                    break;
                case 1: // Medium consumption pattern
                    baseVoltage = 225;
                    baseCurrent = 12;
                    basePower = 2.7;
                    energyIncrement = 2.1;
                    break;
                case 2: // Low consumption pattern
                    baseVoltage = 218;
                    baseCurrent = 8;
                    basePower = 1.8;
                    energyIncrement = 1.2;
                    break;
                case 3: // Variable consumption pattern
                    baseVoltage = 230;
                    baseCurrent = 15;
                    basePower = 3.4;
                    energyIncrement = 2.8;
                    break;
            }
            
            // Add time-of-day variation (higher during day, lower at night)
            const timeOfDayFactor = hour >= 6 && hour <= 22 ? 1.0 : 0.3;
            
            // Add some randomness but keep the pattern distinct
            const l1_voltage = baseVoltage + (Math.random() * 10 - 5);
            const l1_current = baseCurrent * timeOfDayFactor + (Math.random() * 4 - 2);
            const l1_power = basePower * timeOfDayFactor + (Math.random() * 1 - 0.5);
            const l1_energy = 50 + (energyIncrement * day) + (Math.random() * 20);
            
            const l2_voltage = baseVoltage - 2 + (Math.random() * 10 - 5);
            const l2_current = (baseCurrent - 1) * timeOfDayFactor + (Math.random() * 4 - 2);
            const l2_power = (basePower - 0.3) * timeOfDayFactor + (Math.random() * 1 - 0.5);
            const l2_energy = 75 + (energyIncrement * day) + (Math.random() * 20);
            
            const l3_voltage = baseVoltage + 3 + (Math.random() * 10 - 5);
            const l3_current = (baseCurrent + 0.5) * timeOfDayFactor + (Math.random() * 4 - 2);
            const l3_power = (basePower + 0.2) * timeOfDayFactor + (Math.random() * 1 - 0.5);
            const l3_energy = 30 + (energyIncrement * day) + (Math.random() * 20);

            db.prepare(`
                INSERT INTO meter_readings 
                (meter_id, timestamp, l1_voltage, l1_current, l1_power, l1_energy, 
                 l2_voltage, l2_current, l2_power, l2_energy,
                 l3_voltage, l3_current, l3_power, l3_energy) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                meter_id,
                timestamp.toISOString(),
                l1_voltage, l1_current, l1_power, l1_energy,
                l2_voltage, l2_current, l2_power, l2_energy,
                l3_voltage, l3_current, l3_power, l3_energy
            );
        }
    }

    res.redirect("/dashboard?meter_id=" + meter_id);
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
        csv += `"${timestamp}",${row.l1_voltage},${row.l1_current},${row.l1_power},${row.l1_energy},`
        csv += `${row.l2_voltage},${row.l2_current},${row.l2_power},${row.l2_energy},`
        csv += `${row.l3_voltage},${row.l3_current},${row.l3_power},${row.l3_energy}\n`
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

app.post("/register", (req, res) => {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.username = ""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("You must provide a username.")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be atleast 3 characters.")
    if (req.body.username && req.body.username.length > 10) errors.push("Username cannot exceed 10 characters.")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")

        //CHECK IF USERNAME EXISTS ALREADY
        const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
        const usernameCheck = usernameStatement.get(req.body.username)

    if (!req.body.password) errors.push("You must provide a password.")
    if (req.body.password && req.body.password.length < 12) errors.push("Paasword must be atleast 12 characters.")
    if (req.body.password && req.body.password.length > 70) errors.push("Password cannot exceed 70 characters.")

    if (usernameCheck) errors.push("That username already exists.")

    if (errors.length) {
        return res.render("homepage.ejs", {errors})
    } 

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log a user in by giving them a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/dashboard")

})

app.listen(3000, () => {
    console.log("Server running on port 3000")
})
