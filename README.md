# EISA Mock Exam

The app serves the simulated cloud practical, stores each student's progress in SQLite, and creates a downloadable PDF when the student's result is released. It uses Python's standard library, with `pypdf` for restoring student accounts from credentials PDFs.

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

To restore saved accounts, sign in as the teacher and use **Restore saved student credentials** to upload the saved credentials PDF (simple name, student ID, and temporary password columns; up to 50 accounts and 4 MB) or a JSON array of `{ "id": "EISA-XXXXXX", "name": "...", "password": "..." }` records. Existing IDs are skipped without changing their names or passwords.

## Exam workflow

- The simulated **Create a resource** hub lets students create resource groups, virtual networks and subnets, VMs, attached data disks, standard or system Linux users, Microsoft Entra directory users and groups, app registrations, Azure RBAC role assignments, and App Service web apps. For the guide's `camera_bot` account, choose a system account, disable its home directory, and select `/usr/sbin/nologin`; the same steps can also be practised in the VM terminal with `useradd`. Entra identities and role assignments are local learning data, not real Microsoft accounts or an authorization boundary. Web apps are simulated and do not deploy to Azure. VM images include Ubuntu, Debian, AlmaLinux, Red Hat Enterprise Linux, SUSE Linux Enterprise Server, Windows 11 Enterprise, and Windows Server 2022/2025. VM deployment also provisions its NIC, public IP (if selected), network security group, and OS disk.
- The VM image list is for Azure portal/resource-creation practice; the interactive terminal and scored exam tasks remain Ubuntu-based. Students should choose Ubuntu Server 22.04 for the exam.
- **Section A · Theory** provides the 13 written-response questions from the exam. Responses autosave and can also be saved with **Save theory answers**. After submission, students can review and save theory answers for that attempt; if its PDF is already released, it is regenerated with the saved answers. Theory is for facilitator review and is not automatically graded.
- Students sign in using the ID and password issued by the teacher. Their work autosaves to the server and can be resumed on another device.
- Students use **Submit mock exam** on the task panel or Results report. Practical work and marks are locked for that attempt; students may take up to five total attempts, each with a separate result.
- The result is released five minutes after each submission. Students can then download the PDF or open it in a PDF viewer to print. The teacher page lists each attempt and allows released PDFs to be downloaded.
- Marks are generated from the existing 31 simulator checks, weighted equally and rounded to a whole-number mark out of 100. The PDF places Section A theory responses first and Section B practical results after them.

**Assessment limitation:** this is still a browser-based simulator. The mark is an automated simulator score, not proof of real cloud work or a manual assessment of written explanations. Students control their browser, so do not treat this as a tamper-proof or high-stakes examination.
