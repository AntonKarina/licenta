const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: 'g0312@13k',
    database: 'dance_management_db'
});

db.connect((err) => {
    if (err) {
        console.error('Eroare la conectarea la baza de date:', err);
        throw err;
    }
    console.log('Conectat la baza de date dance_management_db');
});

const jwtSecretKey = process.env.JWT_SECRET_KEY || "jwtSecretKey";

const fs = require('fs');
const path = require('path');

// Path-ul către directorul în care se vor salva fișierele
const musicUploadPath = path.join(__dirname, 'uploads/music/');

// Verifică dacă directorul există
if (!fs.existsSync(musicUploadPath)) {
    // Creează directorul dacă nu există
    fs.mkdirSync(musicUploadPath, { recursive: true });
    console.log(`Created directory: ${musicUploadPath}`);
}

// Multer configuration for storing music files on disk
const musicStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/music/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const uploadMusic = multer({ storage: musicStorage });

// Multer configuration for storing profile pictures in memory
const imageStorage = multer.memoryStorage();
const uploadImage = multer({ storage: imageStorage });

const transporter = nodemailer.createTransport({
    service: 'Gmail', // Sau alt serviciu de email
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log('No token provided');
        return res.sendStatus(403);
    }

    jwt.verify(token, jwtSecretKey, (err, user) => {
        if (err) {
            console.log('Token verification failed:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        console.log('Authenticated user:', user);
        next();
    });
};

app.post('/signup', (req, res) => {
    console.log(req.body);
    const sql = `INSERT INTO danceclubs (email, password) VALUES (?, ?)`;
    const values = [
        req.body.email,
        req.body.password
    ];
    db.query(sql, values, (err, data) => {
        if (err) {
            return res.json(err);
        }
        return res.json(data);
    });
});

app.get('/', authenticateToken, (req, res) => {
    return res.json("Authenticated");
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    console.log('Login attempt for:', email);

    const sqlAdmin = `SELECT * FROM admins WHERE email = ? AND password = ?`;
    db.query(sqlAdmin, [email, password], (err, adminData) => {
        if (err) {
            console.error('Error fetching data:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (adminData.length > 0) {
            console.log('Admin login successful:', email);
            const token = jwt.sign({ id: email, role: 'admin', club_id: adminData[0].club_id }, jwtSecretKey, { expiresIn: '1h' });
            console.log('Generated admin token:', token);

            const updateTokenSql = `UPDATE admins SET auth_token = ? WHERE email = ?`;
            db.query(updateTokenSql, [token, email], (updateErr) => {
                if (updateErr) {
                    console.error('Error updating token:', updateErr);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }
                return res.status(200).json({ Login: true, token, role: 'admin' });
            });
        } else {
            const sqlUser = `SELECT * FROM danceclubs WHERE email = ? AND password = ?`;
            db.query(sqlUser, [email, password], (err, userData) => {
                if (err) {
                    console.error('Error fetching data:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }
                if (userData.length > 0) {
                    console.log('User login successful:', email);
                    const token = jwt.sign({ id: email, role: 'user', club_id: userData[0].club_id }, jwtSecretKey, { expiresIn: '1h' });
                    console.log('Generated user token:', token);

                    const updateTokenSql = `UPDATE danceclubs SET auth_token = ? WHERE email = ?`;
                    db.query(updateTokenSql, [token, email], (updateErr) => {
                        if (updateErr) {
                            console.error('Error updating token:', updateErr);
                            return res.status(500).json({ error: 'Internal Server Error' });
                        }
                        return res.status(200).json({ Login: true, token, role: 'user' });
                    });
                } else {
                    console.log('Invalid email or password:', email);
                    return res.status(401).json({ message: 'Invalid email or password' });
                }
            });
        }
    });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    console.log(`Received forgot-password request for email: ${email}`);
    const sql = `SELECT * FROM danceclubs WHERE email = ?`;
    db.query(sql, [email], (err, data) => {
        if (err) {
            console.error('Error fetching data:', err);
            return res.status(500).json({ error: 'Internal Server Error: Database error' });
        }

        if (data.length > 0) {
            console.log('Email found, generating reset token...');
            const token = crypto.randomBytes(20).toString('hex');
            const resetPasswordToken = token;
            const resetPasswordExpires = new Date(Date.now() + 3600000).toLocaleString("ro-RO", { timeZone: "Europe/Bucharest" });

            const updateSql = `UPDATE danceclubs SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?`;
            db.query(updateSql, [resetPasswordToken, resetPasswordExpires, email], (err, data) => {
                if (err) {
                    console.error('Error updating data:', err);
                    return res.status(500).json({ error: 'Internal Server Error: Database update error' });
                }

                const mailOptions = {
                    to: email,
                    from: process.env.EMAIL_USER,
                    subject: 'Password Reset',
                    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                        `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                        `http://localhost:8080/reset-password/${token}\n\n` +
                        `If you did not request this, please ignore this email and your password will remain unchanged.\n`
                };

                transporter.sendMail(mailOptions, (err, response) => {
                    if (err) {
                        console.error('Error sending email:', err);
                        return res.status(500).json({ error: 'Internal Server Error: Email error' });
                    }

                    res.json({ Status: 'Success', message: 'Please check your email for the reset link.' });
                });
            });
        } else {
            res.json({ Status: 'Failure', message: 'Email not found' });
        }
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    const sql = `SELECT * FROM danceclubs WHERE resetPasswordToken = ? AND resetPasswordExpires > ?`;
    db.query(sql, [token, Date.now()], (err, data) => {
        if (err) {
            console.error('Error fetching data:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (data.length > 0) {
            const updateSql = `UPDATE danceclubs SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE resetPasswordToken = ?`;
            db.query(updateSql, [newPassword, token], (err, data) => {
                if (err) {
                    console.error('Error updating data:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }

                res.json({ Status: 'Success', message: 'Password has been reset.' });
            });
        } else {
            res.json({ Status: 'Failure', message: 'Password reset token is invalid or has expired.' });
        }
    });
});

app.get('/profile', authenticateToken, (req, res) => {
    const email = req.user.id;
    const query = `SELECT club_name, trainer_name FROM danceclubs WHERE email = ?`;

    db.query(query, [email], (err, result) => {
        if (err) {
            console.error('Error fetching profile:', err);
            return res.status(500).json({ Status: 'Error', message: 'Internal Server Error' });
        }
        if (result.length > 0) {
            res.json({ Status: 'Success', profile: result[0] });
        } else {
            res.json({ Status: 'Failure', message: 'Profile not found' });
        }
    });
});

app.post('/profile', authenticateToken, (req, res) => {
    const { club_name, trainer_name } = req.body;
    const email = req.user.id;

    const selectQuery = `SELECT * FROM danceclubs WHERE email = ?`;
    const insertQuery = `INSERT INTO danceclubs (club_name, trainer_name, email) VALUES (?, ?, ?)`;
    const updateQuery = `UPDATE danceclubs SET club_name = ?, trainer_name = ? WHERE email = ?`;

    db.query(selectQuery, [email], (selectErr, results) => {
        if (selectErr) {
            console.error('Error checking profile:', selectErr);
            return res.status(500).json({ Status: 'Error', message: 'Internal Server Error' });
        }

        if (results.length > 0) {
            // Record exists, perform update
            db.query(updateQuery, [club_name, trainer_name, email], (updateErr, updateResult) => {
                if (updateErr) {
                    console.error('Error updating profile:', updateErr);
                    return res.status(500).json({ Status: 'Error', message: 'Internal Server Error' });
                }
                res.json({ Status: 'Success', message: 'Profile updated successfully' });
            });
        } else {
            // Record does not exist, perform insert
            db.query(insertQuery, [club_name, trainer_name, email], (insertErr, insertResult) => {
                if (insertErr) {
                    console.error('Error inserting profile:', insertErr);
                    return res.status(500).json({ Status: 'Error', message: 'Internal Server Error' });
                }
                res.json({ Status: 'Success', message: 'Profile created successfully' });
            });
        }
    });
});


app.get('/api/user', authenticateToken, (req, res) => {
    if (!req.user) {
        console.error('User data not available in req.user');
        return res.status(401).json({ error: 'User data not available' });
    }

    console.log('Authenticated user:', req.user.id, req.user.role);

    const sql = `SELECT email, 'admin' as role FROM admins WHERE email = ? UNION SELECT email, 'user' as role FROM danceclubs WHERE email = ?`;
    db.query(sql, [req.user.id, req.user.id], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length > 0) {
            console.log('User found:', results[0]);
            res.json({ user: results[0] });
        } else {
            console.log('User not found');
            res.status(404).json({ error: 'User not found' });
        }
    });
});

app.post('/add-event', (req, res) => {
    const { name, date, location, google_maps_url, deadline, competitions } = req.body;

    console.log('Received request to add event:', req.body);

    const eventSql = `INSERT INTO events (name, date, location, google_maps_url, deadline) VALUES (?, ?, ?, ?, ?)`;
    db.query(eventSql, [name, date, location, google_maps_url, deadline], (err, result) => {
        if (err) {
            console.error('Error adding event:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        const eventId = result.insertId;
        console.log('Event added with ID:', eventId);

        if (competitions && competitions.length > 0) {
            const competitionSql = `INSERT INTO competitions (event_id, name, date) VALUES ?`;
            const competitionValues = competitions.map(competition => [eventId, competition.name, competition.date]);

            console.log('Adding competitions:', competitionValues);

            db.query(competitionSql, [competitionValues], (err, result) => {
                if (err) {
                    console.error('Error adding competitions:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                console.log('Competitions added successfully');
                res.status(201).json({ Status: 'Success', event_id: eventId, name, date, location, google_maps_url, deadline });
            });
        } else {
            res.status(201).json({ Status: 'Success', event_id: eventId, name, date, location, google_maps_url, deadline });
        }
    });
});

app.get('/events', (req, res) => {
    const sql = 'SELECT * FROM events';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching events:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ events: results });
    });
});

app.get('/event/:eventId', authenticateToken, (req, res) => {
    const { eventId } = req.params;

    const sql = `SELECT * FROM events WHERE event_id = ?`;
    db.query(sql, [eventId], (err, result) => {
        if (err) {
            console.error('Error fetching event details:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }
        res.json({ Status: 'Success', event: result[0] });
    });
});

app.put('/event/:eventId', authenticateToken, (req, res) => {
    const { eventId } = req.params;
    const { name, date, location, deadline } = req.body;

    const sql = `UPDATE events SET name = ?, date = ?, location = ?, deadline = ? WHERE event_id = ?`;
    db.query(sql, [name, date, location, deadline, eventId], (err, result) => {
        if (err) {
            console.error('Error updating event:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ Status: 'Success', message: 'Event updated successfully' });
    });
});

app.put('/events/:id/complete', authenticateToken, (req, res) => {
    const { id } = req.params;

    if (req.user.role === 'admin') {
        const sql = `UPDATE events SET status = 'completed' WHERE event_id = ?`;
        db.query(sql, [id], (err, result) => {
            if (err) {
                console.error('Error marking event as completed:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Event not found' });
            }
            res.status(200).json({ message: 'Event marked as completed' });
        });
    } else {
        res.status(403).json({ error: 'Unauthorized' });
    }
});

app.delete('/events/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    if (req.user.role === 'admin') {
        const sql = `DELETE FROM events WHERE event_id = ?`;

        db.query(sql, [id], (err, result) => {
            if (err) {
                console.error('Error deleting event:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(200).json({ message: 'Event deleted successfully' });
        });
    } else {
        res.status(403).json({ error: 'Unauthorized' });
    }
});

app.post('/events/:id/competitions', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, date } = req.body;

    if (req.user.role === 'admin') {
        const sql = `INSERT INTO competitions (event_id, name, date) VALUES (?, ?, ?)`;
        const values = [id, name, date];

        db.query(sql, values, (err, result) => {
            if (err) {
                console.error('Error adding competition:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            console.log('Competition added:', result);
            res.status(201).json({ message: 'Competition added successfully' });
        });
    } else {
        res.status(403).json({ error: 'Unauthorized' });
    }
});

// Endpoint to fetch competitions for a given event
app.get('/events/:eventId/competitions', (req, res) => {
    const eventId = req.params.eventId;

    const competitionSql = `SELECT * FROM competitions WHERE event_id = ?`;
    db.query(competitionSql, [eventId], (err, results) => {
        if (err) {
            console.error('Error fetching competitions:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success', competitions: results });
    });
});

// Endpoint to update a competition
app.put('/competitions/:competitionId', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const { name, date } = req.body;
    
    const updateCompetitionSql = `UPDATE competitions SET name = ?, date = ? WHERE competition_id = ?`;
    db.query(updateCompetitionSql, [name, date, competitionId], (err, result) => {
        if (err) {
            console.error('Error updating competition:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success' });
    });
});

// Endpoint to delete a competition
app.delete('/competitions/:competitionId', authenticateToken, (req, res) => {
    const { competitionId } = req.params;

    const deleteCompetitionSql = `DELETE FROM competitions WHERE competition_id = ?`;
    db.query(deleteCompetitionSql, [competitionId], (err, result) => {
        if (err) {
            console.error('Error deleting competition:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success' });
    });
});

app.get('/participants', authenticateToken, (req, res) => {
    const sql = `SELECT * FROM participants WHERE club_id = ?`;
    db.query(sql, [req.user.club_id], (err, results) => {
        if (err) {
            console.error('Error fetching participants:', err);
            return res.status(500).json({ Status: 'Error', message: 'Internal Server Error' });
        }
        res.json({ Status: 'Success', participants: results });
    });
});

app.post('/participants', authenticateToken, (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { first_name, last_name, age, gender } = req.body;

    if (!['Male', 'Female'].includes(gender)) {
        return res.status(400).json({ error: 'Invalid gender value' });
    }
    
    const sql = `INSERT INTO participants (first_name, last_name, age, gender, club_id) VALUES (?, ?, ?, ?, ?)`;
    db.query(sql, [first_name, last_name, age, gender, req.user.club_id], (err, result) => {
        if (err) {
            console.error('Error adding participant:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ Status: 'Success', participant_id: result.insertId, first_name, last_name, age, gender })
    });
});

app.put('/participants/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { first_name, last_name, age, gender } = req.body;
    const { id } = req.params;

    const sql = `UPDATE participants SET first_name = ?, last_name = ?, age = ?, gender = ? WHERE participant_id = ? AND club_id = ?`;
    db.query(sql, [first_name, last_name, age, gender, id, req.user.club_id], (err, result) => {
        if (err) {
            console.error('Error updating participant:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success', message: 'Participant updated successfully' });
    });
});

// Endpoint to delete a participant
app.delete('/participants/:participantId', authenticateToken, (req, res) => {
    const participantId = req.params.participantId;

    const sql = `DELETE FROM participants WHERE participant_id = ?`;
    db.query(sql, [participantId], (err, result) => {
        if (err) {
            console.error('Error deleting participant:', err);
            return res.status(500).json({ Status: 'Error', Message: 'Database error' });
        }
        res.status(200).json({ Status: 'Success', Message: 'Participant deleted successfully' });
    });
});

app.post('/competitions/:competitionId/register', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const { participantId, groupId, type } = req.body;

    console.log('Registering for competition:', competitionId);
    console.log('Group ID:', groupId);
    console.log('Type:', type);

    if (type !== 'solo') {
        const checkGroupQuery = `SELECT * FROM competition_groups WHERE competition_id = ? AND group_id = ? AND type = ?`;
        db.query(checkGroupQuery, [competitionId, groupId, type], (err, results) => {
            if (err) {
                console.error('Error checking existing registration:', err);
                return res.status(500).json({ error: 'Database error', details: err });
            }
            if (results.length > 0) {
                return res.status(400).json({ error: 'Group is already registered in this competition' });
            }

            const insertGroupQuery = `INSERT INTO competition_groups (competition_id, group_id, type) VALUES (?, ?, ?)`;
            db.query(insertGroupQuery, [competitionId, groupId, type], (err, result) => {
                if (err) {
                    console.error('Error registering group for competition:', err);
                    return res.status(500).json({ error: 'Database error', details: err });
                }
                res.status(201).json({ message: 'Group registered for competition successfully' });
            });
        });
    }
});


app.get('/competitions/:competitionId/participants', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    console.log(`Fetching participants for competition: ${competitionId}`);

    const sql = `
        SELECT p.participant_id, p.first_name, p.last_name, cp.age_category, cp.type, cp.gender
        FROM participants p
        JOIN competition_participants cp ON p.participant_id = cp.participant_id
        WHERE cp.competition_id = ?
    `;

    db.query(sql, [competitionId], (err, results) => {
        if (err) {
            console.error('Error fetching participants for competition:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        console.log('Participants fetched:', results);
        res.json({ participants: results });
    });
});


app.get('/competitions', authenticateToken, (req, res) => {
    const sql = `SELECT * FROM competitions`;
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching competitions:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ competitions: results });
    });
});

app.get('/participants/:participantId/competitions', authenticateToken, (req, res) => {
    const { participantId } = req.params;

    const sql = `
        SELECT c.competition_id, c.name, c.date 
        FROM competitions c
        JOIN competition_participants cp ON c.competition_id = cp.competition_id
        WHERE cp.participant_id = ?
    `;

    db.query(sql, [participantId], (err, results) => {
        if (err) {
            console.error('Error fetching competitions for participant:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ competitions: results });
    });
});


app.get('/clubs', (req, res) => {
    const { club_name, trainer_name } = req.query;

    let sql = `SELECT club_id, club_name, trainer_name, club_profile_pic FROM danceclubs`;
    const filters = [];

    if (club_name) {
        filters.push(`club_name LIKE '%${club_name}%'`);
    }

    if (trainer_name) {
        filters.push(`trainer_name LIKE '%${trainer_name}%'`);
    }

    if (filters.length > 0) {
        sql += ' WHERE ' + filters.join(' AND ');
    }

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching clubs:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        const clubs = results.map(club => ({
            ...club,
            club_profile_pic: club.club_profile_pic ? club.club_profile_pic.toString('base64') : null
        }));

        res.json({ clubs });
    });
});

app.get('/clubs/:id', (req, res) => {
    const { id } = req.params;
    const clubSql = `SELECT club_id, club_name, trainer_name, club_profile_pic FROM danceclubs WHERE club_id = ?`;
    const participantsSql = `SELECT participant_id, first_name, last_name, age, gender FROM participants WHERE club_id = ?`;

    db.query(clubSql, [id], (err, clubResults) => {
        if (err) {
            console.error('Error fetching club:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (clubResults.length === 0) {
            return res.status(404).json({ error: 'Club not found' });
        }

        const club = clubResults[0];
        club.club_profile_pic = club.club_profile_pic ? club.club_profile_pic.toString('base64') : null;

        db.query(participantsSql, [id], (err, participantResults) => {
            if (err) {
                console.error('Error fetching participants:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            club.participants = participantResults;
            res.json({ club });
        });
    });
});


app.get('/groups', authenticateToken, (req, res) => {
    const query = `
        SELECT g.*, p.participant_id, p.first_name, p.last_name 
        FROM groups g
        LEFT JOIN group_participants gp ON g.group_id = gp.group_id
        LEFT JOIN participants p ON gp.participant_id = p.participant_id
        WHERE g.club_id = ?
    `;
    db.query(query, [req.user.club_id], (err, results) => {
        if (err) {
            console.error('Error fetching groups:', err);
            return res.status(500).json({ error: 'Database error', details: err });
        }
        const groups = results.reduce((acc, row) => {
            const group = acc.find(g => g.group_id === row.group_id);
            if (group) {
                if (row.participant_id) {
                    group.participants.push({
                        participant_id: row.participant_id,
                        first_name: row.first_name,
                        last_name: row.last_name
                    });
                }
            } else {
                acc.push({
                    group_id: row.group_id,
                    name: row.name,
                    num_participants: row.num_participants,
                    age_category: row.age_category,
                    type: row.type,
                    participants: row.participant_id ? [{
                        participant_id: row.participant_id,
                        first_name: row.first_name,
                        last_name: row.last_name
                    }] : []
                });
            }
            return acc;
        }, []);
        res.json({ groups });
    });
});

// Endpoint to create a new group
app.post('/groups', authenticateToken, (req, res) => {
    const { name, num_participants, age_category, type } = req.body;
    const club_id = req.user.club_id;

    console.log('Received group data:', { name, num_participants, age_category, type });

    // Validation logic
    if (type === 'Duo' && !(num_participants > 1 && num_participants < 3)) {
        return res.status(400).json({ message: 'Un Duo trebuie să aibă exact 2 participanți.' });
    }

    if (type === 'Trio' && !(num_participants > 2 && num_participants < 4)) {
        return res.status(400).json({ message: 'Un Trio trebuie să aibă exact 3 participanți.' });
    }

    if (type === 'Grup' && num_participants < 4) {
        return res.status(400).json({ message: 'Un Grup trebuie să aibă cel puțin 4 participanți.' });
    }

    const sql = `INSERT INTO groups (name, club_id, num_participants, age_category, type) VALUES (?, ?, ?, ?, ?)`;
    const values = [name, club_id, num_participants, age_category, type];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error('Eroare la inserarea grupului în baza de date:', err);
            return res.status(500).json({ message: 'Eroare la crearea grupului' });
        }
        res.status(201).json({ message: 'Grup creat cu succes', groupId: result.insertId });
    });
});


app.post('/groups/:groupId/participants', authenticateToken, (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { groupId } = req.params;
    const { participantId } = req.body;
    const checkGroupSql = `SELECT * FROM groups WHERE group_id = ? AND club_id = ?`;
    db.query(checkGroupSql, [groupId, req.user.club_id], (err, results) => {
        if (err) {
            console.error('Eroare la verificarea grupului:', err);
            return res.status(500).json({ error: 'Eroare de bază de date' });
        }
        if (results.length === 0) {
            return res.status(403).json({ error: 'Neautorizat' });
        }
        const group = results[0];
        //Verify group target
        const checkParticipantsSql = `SELECT COUNT(*) AS participant_count FROM group_participants WHERE group_id = ?`;
        db.query(checkParticipantsSql, [groupId], (err, result) => {
            if (err) {
                console.error('Eroare la numărarea participanților:', err);
                return res.status(500).json({ error: 'Eroare de bază de date' });
            }
            if (result[0].participant_count >= group.num_participants) {
                return res.status(400).json({ error: `Grupul are deja ${group.num_participants} participanți` });
            }
            const sql = `INSERT INTO group_participants (group_id, participant_id) VALUES (?, ?)`;
            db.query(sql, [groupId, participantId], (err, result) => {
                if (err) {
                    console.error('Eroare la adăugarea participantului în grup:', err);
                    return res.status(500).json({ error: 'Eroare de bază de date' });
                }
                res.status(201).json({ group_id: groupId, participant_id: participantId });
            });
        });
    });
});


app.get('/groups-with-participants', authenticateToken, (req, res) => {
    const sql = `
        SELECT g.group_id, g.name, g.num_participants, 
               p.participant_id, p.first_name, p.last_name 
        FROM groups g 
        LEFT JOIN group_participants gp ON g.group_id = gp.group_id 
        LEFT JOIN participants p ON gp.participant_id = p.participant_id 
        WHERE g.club_id = ?
    `;

    db.query(sql, [req.user.club_id], (err, results) => {
        if (err) {
            console.error('Eroare la preluarea grupurilor:', err);
            return res.status(500).json({ error: 'Eroare de bază de date' });
        }

        const groups = results.reduce((acc, row) => {
            const group = acc.find(g => g.group_id === row.group_id);
            if (group) {
                if (row.participant_id) {
                    group.participants.push({
                        participant_id: row.participant_id,
                        first_name: row.first_name,
                        last_name: row.last_name
                    });
                }
            } else {
                acc.push({
                    group_id: row.group_id,
                    name: row.name,
                    num_participants: row.num_participants,
                    participants: row.participant_id ? [{
                        participant_id: row.participant_id,
                        first_name: row.first_name,
                        last_name: row.last_name
                    }] : []
                });
            }
            return acc;
        }, []);

        res.status(200).json({ groups });
    });
});


app.get('/groups/:groupId/participants-count', authenticateToken, (req, res) => {
    const { groupId } = req.params;

    const sql = `SELECT COUNT(*) AS participant_count FROM group_participants WHERE group_id = ?`;
    db.query(sql, [groupId], (err, results) => {
        if (err) {
            console.error('Error counting participants:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ participant_count: results[0].participant_count });
    });
});


app.get('/groups-with-competitions', authenticateToken, (req, res) => {
    const query = `
        SELECT g.group_id, g.name as group_name, cg.competition_id, c.name as competition_name, cg.music_file
        FROM competition_groups cg
        JOIN groups g ON cg.group_id = g.group_id
        JOIN competitions c ON cg.competition_id = c.competition_id
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching groups with competitions:', err);
            return res.status(500).json({ error: 'Database error', details: err });
        }
        res.json({ groupsWithCompetitions: results });
    });
});


// Endpoint pentru încărcarea imaginii de profil a clubului
app.post('/upload/club-profile-pic', authenticateToken, uploadImage.single('profile_pic'), (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const sql = `UPDATE danceclubs SET club_profile_pic = ? WHERE club_id = ?`;
    db.query(sql, [req.file.buffer, req.user.club_id], (err, result) => {
        if (err) {
            console.error('Error uploading club profile pic:', err);
            return res.status(500).json({ error: 'Database error during profile pic upload' });
        }
        res.status(200).json({ message: 'Club profile pic uploaded successfully' });
    });
});

// Endpoint pentru încărcarea imaginii de profil a antrenorului
app.post('/upload/trainer-profile-pic', authenticateToken, uploadImage.single('profile_pic'), (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const sql = `UPDATE danceclubs SET trainer_profile_pic = ? WHERE club_id = ?`;
    db.query(sql, [req.file.buffer, req.user.club_id], (err, result) => {
        if (err) {
            console.error('Error uploading trainer profile pic:', err);
            return res.status(500).json({ error: 'Database error during profile pic upload' });
        }
        res.status(200).json({ message: 'Trainer profile pic uploaded successfully' });
    });
});

// Endpoint pentru obținerea imaginilor de profil
app.get('/profile-pic/:type', authenticateToken, (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { type } = req.params;
    let column;
    if (type === 'club') {
        column = 'club_profile_pic';
    } else if (type === 'trainer') {
        column = 'trainer_profile_pic';
    } else {
        return res.status(400).json({ error: 'Invalid type' });
    }

    const sql = `SELECT ${column} FROM danceclubs WHERE club_id = ?`;
    db.query(sql, [req.user.club_id], (err, result) => {
        if (err) {
            console.error('Error fetching profile pic:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.length === 0 || !result[0][column]) {
            return res.status(404).json({ error: 'Profile pic not found' });
        }

        res.setHeader('Content-Type', 'image/jpeg'); // Presupunem că imaginile sunt de tip JPEG
        res.send(result[0][column]);
    });
});


app.post('/competition-entries', authenticateToken, uploadMusic.single('musicFile'), (req, res) => {
    console.log('Endpoint /competition-entries hit');
    
    console.log('Request body:', req.body);
    console.log('Uploaded file:', req.file);

    const { competitionId, ageCategory, type, gender, participantId, groupId } = req.body;
    const musicFile = req.file ? req.file.path : null;

    console.log('Received competition entry:', { competitionId, ageCategory, type, gender, participantId, groupId, musicFile });

    try {
        const competitionQuery = `SELECT deadline FROM events JOIN competitions ON events.event_id = competitions.event_id WHERE competition_id = ?`;
        console.log('Executing competition query:', competitionQuery, [competitionId]);
        
        db.query(competitionQuery, [competitionId], (err, competition) => {
            if (err) {
                console.error('Error fetching competition deadline:', err);
                return res.status(500).json({ error: 'Database error', details: err });
            }

            console.log('Competition query result:', competition);
            if (competition.length > 0) {
                const deadline = new Date(competition[0].deadline);
                const now = new Date();
                console.log('Competition deadline:', deadline, 'Current time:', now);

                if (now > deadline) {
                    console.log('The deadline for this competition has passed.');
                    return res.status(400).json({ error: 'The deadline for this competition has passed.' });
                }
            } else {
                console.log('Competition not found.');
                return res.status(404).json({ error: 'Competition not found.' });
            }

            if (type === 'solo') {
                const checkQuery = `SELECT * FROM competition_participants WHERE competition_id = ? AND participant_id = ?`;
                console.log('Executing check query:', checkQuery, [competitionId, participantId]);
                
                db.query(checkQuery, [competitionId, participantId], (err, results) => {
                    if (err) {
                        console.error('Error checking existing participant:', err);
                        return res.status(500).json({ error: 'Database error', details: err });
                    }
                    console.log('Check query result:', results);
                    if (results.length > 0) {
                        console.log('Participant is already registered in this competition');
                        return res.status(400).json({ error: 'Participant is already registered in this competition' });
                    }

                    const insertQuery = `INSERT INTO competition_participants (competition_id, participant_id, age_category, type, gender, music_file) VALUES (?, ?, ?, ?, ?, ?)`;
                    console.log('Executing insert query:', insertQuery, [competitionId, participantId, ageCategory, type, gender, musicFile]);
                    
                    db.query(insertQuery, [competitionId, participantId, ageCategory, type, gender, musicFile], (err, result) => {
                        if (err) {
                            console.error('Error adding entry to competition:', err);
                            return res.status(500).json({ error: 'Database error', details: err });
                        }
                        console.log('Entry added successfully:', result);
                        res.json({ message: 'Entry added successfully' });
                    });
                });
            } else {
                const checkGroupQuery = `SELECT * FROM competition_groups WHERE competition_id = ? AND group_id = ? AND type = ?`;
                console.log('Executing check group query:', checkGroupQuery, [competitionId, groupId, type]);
                
                db.query(checkGroupQuery, [competitionId, groupId, type], (err, results) => {
                    if (err) {
                        console.error('Error checking existing registration:', err);
                        return res.status(500).json({ error: 'Database error', details: err });
                    }
                    console.log('Check group query result:', results);
                    if (results.length > 0) {
                        console.log('Group is already registered in this competition');
                        return res.status(400).json({ error: 'Group is already registered in this competition' });
                    }

                    const insertGroupQuery = `INSERT INTO competition_groups (competition_id, group_id, age_category, type, music_file) VALUES (?, ?, ?, ?, ?)`;
                    console.log('Executing insert group query:', insertGroupQuery, [competitionId, groupId, ageCategory, type, musicFile]);
                    
                    db.query(insertGroupQuery, [competitionId, groupId, ageCategory, type, musicFile], (err, result) => {
                        if (err) {
                            console.error('Error adding group entry to competition:', err);
                            return res.status(500).json({ error: 'Database error', details: err });
                        }
                        console.log('Group entry added successfully:', result);
                        res.json({ message: 'Group entry added successfully' });
                    });
                });
            }
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ error: 'Unexpected error', details: err });
    }
});


app.get('/participants-with-competitions', authenticateToken, (req, res) => {
    const query = `
        SELECT p.participant_id, p.first_name, p.last_name, cp.competition_id, c.name as competition_name, cp.music_file
        FROM competition_participants cp
        JOIN participants p ON cp.participant_id = p.participant_id
        JOIN competitions c ON cp.competition_id = c.competition_id
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching participants with competitions:', err);
            return res.status(500).json({ error: 'Database error', details: err });
        }
        res.json({ participants: results });
    });
});


// Route for adding participants to competitions with deadline validation
app.post('/competition-participants', authenticateToken, (req, res) => {
    const { first_name, last_name, age, gender, event_id, competition_id, type } = req.body;

    // Check the event deadline
    const sqlCheckDeadline = `SELECT deadline FROM events WHERE event_id = ?`;
    db.query(sqlCheckDeadline, [event_id], (err, result) => {
        if (err) {
            console.error('Error checking deadline:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        const deadline = result[0]?.deadline;
        const now = new Date();

        if (deadline && new Date(deadline) < now) {
            return res.status(400).json({ error: 'Registration deadline has passed' });
        }

        // If the deadline is valid, proceed with adding the participant
        const sqlInsert = `INSERT INTO competition_participants (first_name, last_name, age, gender, event_id, competition_id, type) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        db.query(sqlInsert, [first_name, last_name, age, gender, event_id, competition_id, type], (err, result) => {
            if (err) {
                console.error('Error adding competition participant:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.status(201).json({ Status: 'Success', participant_id: result.insertId, first_name, last_name, age, gender });
        });
    });
});

app.get('/competitions/participant-counts', async (req, res) => {
    const query = `
        SELECT competition_id, COUNT(participant_id) as participant_count
        FROM competition_participants
        GROUP BY competition_id;
    `;

    try {
        db.query(query, (error, results) => {
            if (error) {
                console.error('Error fetching participant counts:', error);
                return res.status(500).json({ error: 'Database error', details: error });
            }
            res.json({ participantCounts: results });
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ error: 'Unexpected error', details: err });
    }
});

app.get('/total-participants', (req, res) => {
    const query = 'SELECT COUNT(*) AS total_participants FROM competition_participants;';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching total participants:', err);
            res.status(500).json({ error: 'Internal Server Error', details: err });
        } else {
            res.json({ totalParticipants: results[0].total_participants });
        }
    });
});


app.get('/competitions/:competitionId/participants-count', authenticateToken, (req, res) => {
    const { competitionId } = req.params;

    const query = `
        SELECT 
            (SELECT COUNT(*) FROM competition_participants cp WHERE cp.competition_id = ? AND cp.type = 'solo') AS total_solo_participants,
            (SELECT COUNT(*) FROM competition_groups cg 
             JOIN groups g ON cg.group_id = g.group_id 
             WHERE cg.competition_id = ? AND g.num_participants = 2) AS duos_count,
            (SELECT COUNT(*) FROM competition_groups cg 
             JOIN groups g ON cg.group_id = g.group_id 
             WHERE cg.competition_id = ? AND g.num_participants = 3) AS trios_count,
            (SELECT COUNT(*) FROM competition_groups cg 
             JOIN groups g ON cg.group_id = g.group_id 
             WHERE cg.competition_id = ? AND g.num_participants >= 4) AS groups_count,
            (SELECT COUNT(gp.participant_id)
             FROM competition_groups cg
             JOIN groups g ON cg.group_id = g.group_id
             LEFT JOIN group_participants gp ON g.group_id = gp.group_id
             WHERE cg.competition_id = ?) AS total_group_participants
    `;

    db.query(query, [competitionId, competitionId, competitionId, competitionId, competitionId], (err, results) => {
        if (err) {
            console.error('Error fetching participant count:', err);
            return res.status(500).json({ error: 'Database error', details: err });
        }

        const counts = results[0];
        const total_participants = counts.total_solo_participants + counts.total_group_participants;

        res.json({
            total_participants: total_participants,
            duos_count: counts.duos_count,
            trios_count: counts.trios_count,
            groups_count: counts.groups_count,
            total_solo_participants: counts.total_solo_participants,
            total_group_participants: counts.total_group_participants
        });
    });
});


app.post('/participants/:participantId/schedule', async (req, res) => {
    const participantId = req.params.participantId;
    const { scheduleTime } = req.body;

    try {
        await db.query(
            `UPDATE competition_participants SET schedule_time = ? WHERE participant_id = ?`,
            [scheduleTime, participantId]
        );
        res.status(200).json({ message: 'Schedule time updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/competitions/:competitionId/groups', authenticateToken, (req, res) => {
    const competitionId = req.params.competitionId;

    const query = `
        SELECT g.*, gp.participant_id, p.first_name, p.last_name, p.age, p.gender
        FROM competition_groups cg
        JOIN groups g ON cg.group_id = g.group_id
        LEFT JOIN group_participants gp ON g.group_id = gp.group_id
        LEFT JOIN participants p ON gp.participant_id = p.participant_id
        WHERE cg.competition_id = ?
    `;

    db.query(query, [competitionId], (err, results) => {
        if (err) {
            return res.status(500).send({ message: 'Database error', error: err });
        }

        const groups = results.reduce((acc, row) => {
            let group = acc.find(g => g.group_id === row.group_id);
            if (!group) {
                group = {
                    group_id: row.group_id,
                    name: row.name,
                    club_id: row.club_id,
                    num_participants: row.num_participants,
                    age_category: row.age_category,
                    type: row.type,
                    participants: []
                };
                acc.push(group);
            }

            if (row.participant_id) {
                group.participants.push({
                    participant_id: row.participant_id,
                    first_name: row.first_name,
                    last_name: row.last_name,
                    age: row.age,
                    gender: row.gender
                });
            }

            return acc;
        }, []);

        res.send({ groups });
    });
});

// Endpoint to save solo schedule
app.post('/competitions/:competitionId/schedule', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const schedule = req.body.schedule; // Assumes schedule is an object with participantId as keys and time as values

    const values = Object.entries(schedule).map(([participantId, time]) => [competitionId, participantId, time]);

    const sql = `
        INSERT INTO schedules (competition_id, participant_id, schedule_time) VALUES ?
        ON DUPLICATE KEY UPDATE schedule_time = VALUES(schedule_time)
    `;

    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error('Error saving schedule:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Schedule saved successfully' });
    });
});

// Endpoint to save group schedule
app.post('/competitions/:competitionId/group_schedule', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const schedule = req.body.schedule; // Assumes schedule is an object with groupId as keys and time as values

    const values = Object.entries(schedule).map(([groupId, time]) => [competitionId, groupId, time]);

    const sql = `
        INSERT INTO group_schedules (competition_id, group_id, schedule_time) VALUES ?
        ON DUPLICATE KEY UPDATE schedule_time = VALUES(schedule_time)
    `;

    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error('Error saving group schedule:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Group schedule saved successfully' });
    });
});


app.get('/competitions/:competitionId/schedule', authenticateToken, (req, res) => {
    const { competitionId } = req.params;

    const sql = `
        SELECT p.first_name, p.last_name, s.schedule_time
        FROM schedules s
        JOIN participants p ON s.participant_id = p.participant_id
        WHERE s.competition_id = ?
    `;

    db.query(sql, [competitionId], (err, results) => {
        if (err) {
            console.error('Error fetching schedule:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        const schedule = results.map(row => ({
            first_name: row.first_name,
            last_name: row.last_name,
            schedule_time: row.schedule_time
        }));
        res.json({ soloSchedule: schedule });
    });
});

app.get('/competitions/:competitionId/group_schedule', authenticateToken, (req, res) => {
    const { competitionId } = req.params;

    const sql = `
        SELECT g.group_name, gs.schedule_time
        FROM group_schedules gs
        JOIN groups g ON gs.group_id = g.group_id
        WHERE gs.competition_id = ?
    `;

    console.log(`Fetching group schedule for competition_id: ${competitionId}`);
    
    db.query(sql, [competitionId], (err, results) => {
        if (err) {
            console.error('Error fetching group schedule:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!results.length) {
            console.log('No group schedule found for competition_id:', competitionId);
            return res.status(404).json({ error: 'No group schedule found' });
        }

        const schedule = results.map(row => ({
            group_name: row.group_name,
            schedule_time: row.schedule_time
        }));
        
        console.log('Group schedule fetched successfully:', schedule); 
        res.json({ groupSchedule: schedule });
    });
});


// Fetch participants for a specific competition
app.get('/competitions/:competitionId/participants', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const participantsSql = `
        SELECT p.participant_id, p.first_name, p.last_name, 'solo' AS type
        FROM participants p
        JOIN competition_participants cp ON p.participant_id = cp.participant_id
        WHERE cp.competition_id = ?
        UNION ALL
        SELECT g.group_id AS participant_id, g.name AS first_name, '' AS last_name, 'group' AS type
        FROM groups g
        JOIN competition_groups cg ON g.group_id = cg.group_id
        WHERE cg.competition_id = ?
    `;

    db.query(participantsSql, [competitionId, competitionId], (err, results) => {
        if (err) {
            console.error('Error fetching participants:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success', participants: results });
    });
});

// Submit competition results
app.post('/competitions/:competitionId/results', authenticateToken, (req, res) => {
    const { competitionId } = req.params;
    const { results } = req.body;

    const insertResultSql = `INSERT INTO results (competition_id, participant_id, score, placement) VALUES ?`;
    const resultValues = results.map(result => [competitionId, result.entity_id, result.score, result.place]);

    db.query(insertResultSql, [resultValues], (err, result) => {
        if (err) {
            console.error('Error saving results:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ Status: 'Success' });
    });
});


// Fetch completed events
app.get('/events/completed', authenticateToken, (req, res) => {
    const completedEventsSql = `SELECT * FROM events WHERE status = 'completed'`;
    db.query(completedEventsSql, (err, results) => {
        if (err) {
            console.error('Error fetching completed events:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json({ Status: 'Success', events: results });
    });
});

// Fetch all results for a specific competition with event details
app.get('/api/competitions/:competitionId/results', (req, res) => {
    const { competitionId } = req.params;
    const sql = `
        SELECT r.*, c.name AS competition_name, e.name AS event_name
        FROM results r
        INNER JOIN competitions c ON r.competition_id = c.competition_id
        INNER JOIN events e ON c.event_id = e.event_id
        WHERE r.competition_id = ?;
    `;

    db.query(sql, [competitionId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error', details: err });
        res.json({ results });
    });
});

app.post('/api/results', (req, res) => {
    const { competition_id, event_id, results, group_results } = req.body;

    if (!competition_id || !event_id || (!results && !group_results)) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const individualValues = results ? results.map(result => [competition_id, event_id, result.participant_id, result.score, result.placement]) : [];
    const groupValues = group_results ? group_results.map(result => [competition_id, event_id, result.group_id, result.score, result.placement]) : [];

    const individualSql = 'INSERT INTO results (competition_id, event_id, participant_id, score, placement) VALUES ? ON DUPLICATE KEY UPDATE score=VALUES(score), placement=VALUES(placement)';
    const groupSql = 'INSERT INTO group_results (competition_id, event_id, group_id, score, placement) VALUES ? ON DUPLICATE KEY UPDATE score=VALUES(score), placement=VALUES(placement)';

    if (individualValues.length > 0) {
        db.query(individualSql, [individualValues], (err, result) => {
            if (err) {
                console.error('Error saving individual results:', err.message, err.code);
                return res.status(500).json({ error: 'Database error', message: err.message, code: err.code });
            }
        });
    }

    if (groupValues.length > 0) {
        db.query(groupSql, [groupValues], (err, result) => {
            if (err) {
                console.error('Error saving group results:', err.message, err.code);
                return res.status(500).json({ error: 'Database error', message: err.message, code: err.code });
            }
            res.status(201).json({ message: 'Results saved successfully' });
        });
    } else {
        res.status(201).json({ message: 'Results saved successfully' });
    }
});


app.put('/api/results/:resultId', authenticateToken, (req, res) => {
    const { resultId } = req.params;
    const { score, placement } = req.body;

    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const individualSql = `UPDATE results SET score = ?, placement = ? WHERE result_id = ?`;
    const groupSql = `UPDATE group_results SET score = ?, placement = ? WHERE result_id = ?`;

    db.query(individualSql, [score, placement, resultId], (err, result) => {
        if (err) {
            console.error('Error updating result:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.affectedRows === 0) {
            db.query(groupSql, [score, placement, resultId], (err, result) => {
                if (err) {
                    console.error('Error updating group result:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                res.json({ Status: 'Success', message: 'Result updated successfully' });
            });
        } else {
            res.json({ Status: 'Success', message: 'Result updated successfully' });
        }
    });
});


app.delete('/api/results/:resultId', authenticateToken, (req, res) => {
    const { resultId } = req.params;

    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const individualSql = `DELETE FROM results WHERE result_id = ?`;
    const groupSql = `DELETE FROM group_results WHERE result_id = ?`;

    db.query(individualSql, [resultId], (err, result) => {
        if (err) {
            console.error('Error deleting result:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.affectedRows === 0) {
            db.query(groupSql, [resultId], (err, result) => {
                if (err) {
                    console.error('Error deleting group result:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                res.json({ Status: 'Success', message: 'Result deleted successfully' });
            });
        } else {
            res.json({ Status: 'Success', message: 'Result deleted successfully' });
        }
    });
});


app.get('/competitions', authenticateToken, (req, res) => {
   // const sql = `SELECT * FROM competitions`;
   const sql = `SELECT competition_id, name FROM competitions`;
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching competitions:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ competitions: results });
    });
});


app.get('/api/results', (req, res) => {
    const sql = `
        SELECT r.result_id, r.competition_id, r.participant_id, r.score, r.placement, 
               c.name as competition_name, 
               p.first_name, p.last_name, 
               e.event_id, e.name as event_name,
               NULL as group_id, NULL as group_name
        FROM results r
        JOIN competitions c ON r.competition_id = c.competition_id
        JOIN participants p ON r.participant_id = p.participant_id
        LEFT JOIN events e ON r.event_id = e.event_id
        UNION
        SELECT gr.result_id, gr.competition_id, NULL as participant_id, gr.score, gr.placement, 
               c.name as competition_name, 
               NULL as first_name, NULL as last_name, 
               e.event_id, e.name as event_name,
               g.group_id, g.name as group_name
        FROM group_results gr
        JOIN competitions c ON gr.competition_id = c.competition_id
        JOIN groups g ON gr.group_id = g.group_id
        LEFT JOIN events e ON gr.event_id = e.event_id
    `;

    console.log('Executing SQL query:', sql); // Log the SQL query

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching results:', err); // Log the full error
            return res.status(500).json({ error: 'Database error', message: err.message });
        }

        const groupedResults = results.reduce((acc, row) => {
            if (!acc[row.event_id]) {
                acc[row.event_id] = {
                    event_id: row.event_id,
                    event_name: row.event_name,
                    competitions: {}
                };
            }
            if (!acc[row.event_id].competitions[row.competition_id]) {
                acc[row.event_id].competitions[row.competition_id] = {
                    competition_id: row.competition_id,
                    competition_name: row.competition_name,
                    participants: [],
                    groups: []
                };
            }
            if (row.participant_id) {
                acc[row.event_id].competitions[row.competition_id].participants.push({
                    participant_id: row.participant_id,
                    first_name: row.first_name,
                    last_name: row.last_name,
                    score: row.score,
                    placement: row.placement,
                    result_id: row.result_id
                });
            }
            if (row.group_id) {
                acc[row.event_id].competitions[row.competition_id].groups.push({
                    group_id: row.group_id,
                    group_name: row.group_name,
                    score: row.score,
                    placement: row.placement,
                    result_id: row.result_id
                });
            }
            return acc;
        }, {});
        res.json({ Status: 'Success', results: groupedResults });
    });
});


app.get('/api/awards', authenticateToken, (req, res) => {
    const competitionId = req.query.competitionId;

    const soloQuery = `
        SELECT dc.club_name, COUNT(*) AS medals, r.placement
        FROM results r
        JOIN participants p ON r.participant_id = p.participant_id
        JOIN danceclubs dc ON p.club_id = dc.club_id
        WHERE r.competition_id = ? AND r.placement IN (1, 2, 3)
        GROUP BY dc.club_name, r.placement
    `;

    const groupQuery = `
        SELECT dc.club_name, COUNT(*) AS cups, gr.placement
        FROM group_results gr
        JOIN groups g ON gr.group_id = g.group_id
        JOIN danceclubs dc ON g.club_id = dc.club_id
        WHERE gr.competition_id = ? AND gr.placement IN (1, 2, 3)
        GROUP BY dc.club_name, gr.placement
    `;

    db.query(soloQuery, [competitionId], (err, soloResults) => {
        if (err) {
            console.error('Error fetching solo awards:', err);
            return res.status(500).json({ error: 'Database error', message: err.message });
        }

        console.log('Solo Results:', soloResults); // Log solo results

        db.query(groupQuery, [competitionId], (err, groupResults) => {
            if (err) {
                console.error('Error fetching group awards:', err);
                return res.status(500).json({ error: 'Database error', message: err.message });
            }

            console.log('Group Results:', groupResults); // Log group results

            const awards = {};

            soloResults.forEach(row => {
                if (!awards[row.club_name]) {
                    awards[row.club_name] = { medals: 0, cups: 0 };
                }
                awards[row.club_name].medals += row.medals;
            });

            groupResults.forEach(row => {
                if (!awards[row.club_name]) {
                    awards[row.club_name] = { medals: 0, cups: 0 };
                }
                awards[row.club_name].cups += row.cups;
            });

            console.log('Awards:', awards); // Log final awards object

            res.json({ Status: 'Success', awards });
        });
    });
});


// Endpoint pentru a obține suma de plată pentru fiecare participant, duo/trio și grup
app.get('/api/payment-summary', authenticateToken, (req, res) => {
    const clubId = req.user.club_id;

    const sql = `
    SELECT cp.competition_id, cp.participant_id, 'solo' AS type, COUNT(cp.competition_id) AS competition_count, c.name AS competition_name, e.name AS event_name, p.first_name, p.last_name
    FROM competition_participants cp
    JOIN participants p ON cp.participant_id = p.participant_id
    JOIN competitions c ON cp.competition_id = c.competition_id
    JOIN events e ON c.event_id = e.event_id
    WHERE p.club_id = ? AND cp.type = 'solo'
    GROUP BY cp.participant_id, c.name, cp.competition_id, e.name, p.first_name, p.last_name

    UNION

    SELECT cg.competition_id, cg.group_id AS participant_id, cg.type, COUNT(cg.competition_id) AS competition_count, c.name AS competition_name, e.name AS event_name, g.name AS group_name, '' AS last_name
    FROM competition_groups cg
    JOIN groups g ON cg.group_id = g.group_id
    JOIN competitions c ON cg.competition_id = c.competition_id
    JOIN events e ON c.event_id = e.event_id
    WHERE g.club_id = ?
    GROUP BY cg.group_id, cg.type, c.name, cg.competition_id, e.name, g.name;
    `;

    db.query(sql, [clubId, clubId], (err, results) => {
        if (err) {
            console.error('Error fetching payment summary:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        const summary = results.map(row => {
            let price = 20; // Default price for solo
            if (row.type === 'duo' || row.type === 'trio') price = 30;
            if (row.type === 'group') price = 50;
            return {
                id: row.participant_id,
                type: row.type,
                competitionCount: row.competition_count,
                competitionName: row.competition_name,
                eventName: row.event_name,
                name: row.first_name ? `${row.first_name} ${row.last_name}` : row.group_name,
                price: price * row.competition_count
            };
        });

        res.json({ Status: 'Success', summary: summary });
    });
});


app.post('/api/payment', async (req, res) => {
    const { cardNumber, cardName, expiryDate, cvv, competitionId, participantId } = req.body;

    // Add validation for card details if needed

    const paymentQuery = `
        INSERT payments
        SET card_number = ?, card_name = ?, expiry_date = ?, cvv = ?, paid = 1
        WHERE competition_id = ? AND participant_id = ?
    `;

    try {
        await db.query(paymentQuery, [cardNumber, cardName, expiryDate, cvv, competitionId, participantId]);
        res.json({ Status: 'Success', message: 'Payment processed successfully.' });
    } catch (error) {
        console.error('Error processing payment:', error);
        res.status(500).json({ Status: 'Failure', message: 'Payment failed. Please try again.' });
    }
});


app.get('/public-schedule/:competitionId', (req, res) => {
    const { competitionId } = req.params;

    const sqlSolo = `
        SELECT 
            s.schedule_time, 
            p.first_name, 
            p.last_name 
        FROM schedules s
        JOIN participants p ON s.participant_id = p.participant_id
        WHERE s.competition_id = ? AND NOW() > (
            SELECT deadline FROM events e
            JOIN competitions c ON e.event_id = c.event_id
            WHERE c.competition_id = ?
        )
    `;

    const sqlGroup = `
        SELECT 
            gs.schedule_time, 
            g.name as group_name
        FROM group_schedules gs
        JOIN groups g ON gs.group_id = g.group_id
        WHERE gs.competition_id = ? AND NOW() > (
            SELECT deadline FROM events e
            JOIN competitions c ON e.event_id = c.event_id
            WHERE c.competition_id = ?
        )
    `;

    db.query(sqlSolo, [competitionId, competitionId], (err, soloResults) => {
        if (err) {
            console.error('Error fetching solo schedule:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        console.log('Solo Schedule:', soloResults);

        db.query(sqlGroup, [competitionId, competitionId], (err, groupResults) => {
            if (err) {
                console.error('Error fetching group schedule:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            console.log('Group Schedule:', groupResults);

            res.json({ soloSchedule: soloResults, groupSchedule: groupResults });
        });
    });
});


const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
