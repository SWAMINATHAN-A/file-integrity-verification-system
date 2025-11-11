import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;
const HMAC_KEY = process.env.HMAC_KEY || "SECRET_KEY_456";

app.use(helmet());
app.use(cors({
  origin: 'https://swaminathan-a.github.io',
  credentials: true
}));


app.use(express.json());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: 'Too many requests from this IP, please try again later.'
});

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname);
    cb(null, `${randomName}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

function computeHashes(filePath) {
  return new Promise((resolve, reject) => {
    const sha256Hash = crypto.createHash('sha256');
    const salt = crypto.randomBytes(16);
    const saltHex = salt.toString('hex');

    const fileStream = fs.createReadStream(filePath);

    fileStream.on('data', (chunk) => {
      sha256Hash.update(chunk);
    });

    fileStream.on('end', () => {
      const sha256 = sha256Hash.digest('hex');

      const hmac = crypto.createHmac('sha256', HMAC_KEY);
      hmac.update(sha256);
      hmac.update(salt);
      const hmacHash = hmac.digest('hex');

      const verificationCode = hmacHash.substring(0, 16);

      resolve({
        sha256,
        hmac: hmacHash,
        salt: saltHex,
        verificationCode
      });
    });

    fileStream.on('error', (err) => {
      reject(err);
    });
  });
}

function computeHashesWithSalt(filePath, saltHex) {
  return new Promise((resolve, reject) => {
    const sha256Hash = crypto.createHash('sha256');
    const salt = Buffer.from(saltHex, 'hex');

    const fileStream = fs.createReadStream(filePath);

    fileStream.on('data', (chunk) => {
      sha256Hash.update(chunk);
    });

    fileStream.on('end', () => {
      const sha256 = sha256Hash.digest('hex');

      const hmac = crypto.createHmac('sha256', HMAC_KEY);
      hmac.update(sha256);
      hmac.update(salt);
      const hmacHash = hmac.digest('hex');

      const verificationCode = hmacHash.substring(0, 16);

      resolve({
        sha256,
        hmac: hmacHash,
        verificationCode
      });
    });

    fileStream.on('error', (err) => {
      reject(err);
    });
  });
}

app.post('/generate-code', limiter, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const originalName = req.file.originalname;
    const fileSize = req.file.size;

    const hashes = await computeHashes(filePath);

    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting file:', err);
    });

    res.json({
      fileName: originalName,
      fileSize,
      sha256: hashes.sha256,
      hmac: hashes.hmac,
      salt: hashes.salt,
      verificationCode: hashes.verificationCode
    });

  } catch (error) {
    console.error('Error generating code:', error);
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    res.status(500).json({ error: 'Failed to generate verification code' });
  }
});

app.post('/verify-code', limiter, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { code, salt } = req.body;

    if (!code || !salt) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: 'Verification code and salt are required' });
    }

    const filePath = req.file.path;
    const originalName = req.file.originalname;
    const fileSize = req.file.size;

    const hashes = await computeHashesWithSalt(filePath, salt);

    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting file:', err);
    });

    const providedCodeBuffer = Buffer.from(code, 'utf8');
    const computedCodeBuffer = Buffer.from(hashes.verificationCode, 'utf8');

    let match = false;
    if (providedCodeBuffer.length === computedCodeBuffer.length) {
      match = crypto.timingSafeEqual(providedCodeBuffer, computedCodeBuffer);
    }

    res.json({
      fileName: originalName,
      fileSize,
      match,
      computedCode: hashes.verificationCode,
      sha256: hashes.sha256,
      hmac: hashes.hmac
    });

  } catch (error) {
    console.error('Error verifying code:', error);
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    res.status(500).json({ error: 'Failed to verify file' });
  }
});

app.post('/compare-files', limiter, upload.fields([
  { name: 'file1', maxCount: 1 },
  { name: 'file2', maxCount: 1 }
]), async (req, res) => {
  try {
    if (!req.files || !req.files.file1 || !req.files.file2) {
      return res.status(400).json({ error: 'Two files are required' });
    }

    const file1Path = req.files.file1[0].path;
    const file2Path = req.files.file2[0].path;

    const file1Name = req.files.file1[0].originalname;
    const file2Name = req.files.file2[0].originalname;

    const hashes1 = await computeHashes(file1Path);
    const hashes2 = await computeHashes(file2Path);

    fs.unlink(file1Path, (err) => {
      if (err) console.error('Error deleting file1:', err);
    });
    fs.unlink(file2Path, (err) => {
      if (err) console.error('Error deleting file2:', err);
    });

    const match = hashes1.sha256 === hashes2.sha256;

    res.json({
      match,
      file1: {
        name: file1Name,
        sha256: hashes1.sha256,
        hmac: hashes1.hmac
      },
      file2: {
        name: file2Name,
        sha256: hashes2.sha256,
        hmac: hashes2.hmac
      }
    });

  } catch (error) {
    console.error('Error comparing files:', error);
    if (req.files) {
      if (req.files.file1) fs.unlink(req.files.file1[0].path, () => {});
      if (req.files.file2) fs.unlink(req.files.file2[0].path, () => {});
    }
    res.status(500).json({ error: 'Failed to compare files' });
  }
});

app.post('/download-report', express.json(), (req, res) => {
  try {
    const { reportData } = req.body;

    if (!reportData) {
      return res.status(400).json({ error: 'Report data is required' });
    }

    let report = `═══════════════════════════════════════════════════════════════
    FILE INTEGRITY VERIFICATION REPORT
═══════════════════════════════════════════════════════════════

Generated: ${new Date().toLocaleString()}

`;

    if (reportData.type === 'sender') {
      report += `SENDER MODE - VERIFICATION CODE GENERATION
-----------------------------------------------------------

File Information:
  • File Name: ${reportData.fileName}
  • File Size: ${reportData.fileSize} bytes

Cryptographic Hashes:
  • SHA-256: ${reportData.sha256}
  • HMAC-SHA-256: ${reportData.hmac}
  • Salt (Hex): ${reportData.salt}
  • Verification Code: ${reportData.verificationCode}

Process Explanation:
1. File was read in binary stream format
2. SHA-256 hash computed using crypto.createHash("sha256")
3. Random 16-byte salt generated for additional security
4. HMAC-SHA-256 computed using:
   - HMAC Key: SECRET_KEY_456
   - Input: SHA-256 hash + Salt
5. Verification code extracted (first 16 characters of HMAC)

This verification code should be shared with the receiver
to verify file integrity after transmission.
`;
    } else if (reportData.type === 'receiver') {
      report += `RECEIVER MODE - FILE VERIFICATION
-----------------------------------------------------------

File Information:
  • File Name: ${reportData.fileName}
  • File Size: ${reportData.fileSize} bytes

Verification Details:
  • Provided Code: ${reportData.providedCode}
  • Computed Code: ${reportData.computedCode}
  • Salt Used: ${reportData.salt}

Cryptographic Hashes:
  • SHA-256: ${reportData.sha256}
  • HMAC-SHA-256: ${reportData.hmac}

VERIFICATION RESULT: ${reportData.match ? '✓ FILE INTEGRITY MAINTAINED' : '✗ FILE CORRUPTED'}

Process Explanation:
1. Received file was read in binary stream format
2. SHA-256 hash computed using crypto.createHash("sha256")
3. Same salt from sender used for consistency
4. HMAC-SHA-256 computed using:
   - HMAC Key: SECRET_KEY_456
   - Input: SHA-256 hash + Salt
5. Verification code extracted (first 16 characters of HMAC)
6. Timing-safe comparison performed using crypto.timingSafeEqual()

${reportData.match
  ? 'The verification codes match, confirming the file has not been\naltered during transmission.'
  : 'The verification codes DO NOT match, indicating the file may have\nbeen corrupted or tampered with during transmission.'}
`;
    } else if (reportData.type === 'comparison') {
      report += `DIRECT FILE COMPARISON MODE
-----------------------------------------------------------

File 1 Information:
  • File Name: ${reportData.file1Name}
  • SHA-256: ${reportData.file1Sha256}
  • HMAC-SHA-256: ${reportData.file1Hmac}

File 2 Information:
  • File Name: ${reportData.file2Name}
  • SHA-256: ${reportData.file2Sha256}
  • HMAC-SHA-256: ${reportData.file2Hmac}

COMPARISON RESULT: ${reportData.match ? '✓ FILES ARE IDENTICAL' : '✗ FILES ARE DIFFERENT'}

Process Explanation:
1. Both files were read in binary stream format
2. SHA-256 hashes computed independently for each file
3. Hash values compared for equality

${reportData.match
  ? 'The SHA-256 hashes match exactly, confirming both files are identical\nat the binary level.'
  : 'The SHA-256 hashes are different, indicating the files have different\ncontent or have been modified.'}
`;
    }

    report += `

═══════════════════════════════════════════════════════════════
    TECHNICAL INFORMATION
═══════════════════════════════════════════════════════════════

Hashing Algorithm: SHA-256 (Secure Hash Algorithm 256-bit)
  • Cryptographic hash function
  • Produces 256-bit (64 hexadecimal characters) hash value
  • Collision-resistant and deterministic
  • Any change in input produces completely different output

HMAC (Hash-based Message Authentication Code):
  • Uses SHA-256 as the underlying hash function
  • Provides both integrity and authenticity verification
  • Requires secret key known only to sender and receiver
  • Resistant to length extension attacks

Salt:
  • Random 16-byte value added to hash computation
  • Prevents rainbow table attacks
  • Ensures uniqueness even for identical files
  • Must be shared between sender and receiver

Security Features:
  • Timing-safe comparison prevents timing attacks
  • Secure random number generation for salt
  • HMAC key protection
  • File size limit: 50 MB
  • Rate limiting: 10 requests per minute

═══════════════════════════════════════════════════════════════
Project: File Integrity Verification System
Developed by: Richika Rani (24BCE1498), Nandani (24BCE1491)
Guide: Dr. Swaminathan A
Course: Computer Networks
═══════════════════════════════════════════════════════════════
`;

    const reportPath = path.join(__dirname, 'uploads', `Integrity_Report_${Date.now()}.txt`);

    fs.writeFileSync(reportPath, report);

    res.download(reportPath, 'Integrity_Report.txt', (err) => {
      if (err) {
        console.error('Error downloading report:', err);
      }
      fs.unlink(reportPath, (unlinkErr) => {
        if (unlinkErr) console.error('Error deleting report file:', unlinkErr);
      });
    });

  } catch (error) {
    console.error('Error generating report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'File Integrity Verification System API' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
