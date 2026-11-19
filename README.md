# EISA Mock Exam

The app serves the simulated cloud practical, stores each student's progress in SQLite, and creates a downloadable PDF when the student's result is released. It uses Python's standard library.

## Run locally

1. Install Python 3.12 or newer.
2. Set `TEACHER_PASSWORD` to a private password of at least 12 characters.
3. Run `python server.py` from this folder.
4. Open `http://localhost:8080`. Do not open `index.html` directly from File Explorer; sign-in requires the server.
5. Open **Teacher sign in** and create student accounts, one name per line.

Local data and generated PDFs are stored in the `data` folder. Keep this folder private and backed up.

## Deploy to Railway

1. Push this folder to a private GitHub repository and create a Railway project from that repository.
2. In the Railway service variables, set `TEACHER_PASSWORD` to a strong, unique password. Railway supplies `PORT`.
3. Add a Railway **Volume** to the service and mount it at `/data`.
4. Set the service variable `DATA_DIR` to `/data`.
5. Deploy. The health check is `/api/health`; Railway starts the service with `python server.py`.
6. Open the public Railway URL, visit **Teacher sign in**, and create accounts for the class. Download or print the generated credentials and distribute each student's details privately.

The SQLite database and result PDFs are stored on the volume, so they persist across deploys. Do not remove the volume or run multiple service replicas against this SQLite database. Back up the volume; it contains student names, work, marks, and evidence.

## Exam workflow

- The simulated **Create a resource** hub lets students create resource groups, virtual networks and subnets, VMs, and attached data disks. VM deployment also provisions its NIC, public IP (if selected), network security group, and OS disk.
- **Section A · Theory** provides the 13 written-response questions from the exam. Responses autosave and are included in the submission PDF for facilitator review; they are not automatically graded.
- Students sign in using the ID and password issued by the teacher. Their work autosaves to the server and can be resumed on another device.
- Students use **Submit mock exam** on the task panel or Results report. Submission locks their work.
- The result is released five minutes after submission. The student can then download the PDF or open it in a PDF viewer to print. The teacher page lists released marks and allows PDF downloads.
- Marks are generated from the existing 31 simulator checks, weighted equally and rounded to a whole-number mark out of 100. The PDF includes the submitted checks and captured evidence.

**Assessment limitation:** this is still a browser-based simulator. The mark is an automated simulator score, not proof of real cloud work or a manual assessment of written explanations. Students control their browser, so do not treat this as a tamper-proof or high-stakes examination.
