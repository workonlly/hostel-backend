CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'room_type_enum') THEN
        CREATE TYPE room_type_enum AS ENUM ('Student');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS hostel (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                  VARCHAR(255) UNIQUE NOT NULL,
    type                  VARCHAR(100),
    total_capacity        INT DEFAULT 0,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    local_outpass_cutoff  TIME NOT NULL DEFAULT '17:00:00'
);

CREATE TABLE IF NOT EXISTS room (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostel_id         UUID NOT NULL REFERENCES hostel(id) ON DELETE RESTRICT,
    room_number       VARCHAR(50) NOT NULL,
    block             VARCHAR(50) DEFAULT NULL,
    room_type         room_type_enum DEFAULT 'Student',
    max_capacity      INT NOT NULL CHECK (max_capacity IN (1, 2, 3, 4, 5, 6)),
    current_occupancy INT DEFAULT 0 CHECK (current_occupancy >= 0 AND current_occupancy <= max_capacity),
    UNIQUE(hostel_id, block, room_number)
);

CREATE TABLE IF NOT EXISTS students(
    id                TEXT PRIMARY KEY,
    name              VARCHAR(255) NOT NULL,
    father_name       VARCHAR(255),
    email             VARCHAR(255) UNIQUE,
    password          VARCHAR(255),
    hostel            VARCHAR(255) NOT NULL REFERENCES hostel(name) ON DELETE CASCADE,
    hostel_id         UUID NOT NULL REFERENCES hostel(id) ON DELETE CASCADE,
    roll_no           VARCHAR(100) UNIQUE,
    phone             VARCHAR(255),
    parent_number     VARCHAR(20),
    category          VARCHAR(50),
    blood_group       VARCHAR(10),
    state             VARCHAR(100),
    address           TEXT,
    pincode           VARCHAR(20),
    department        VARCHAR(255) NOT NULL,
    cgpa              NUMERIC(4,2),
    joining_year      INTEGER,
    current_year      INTEGER,
    individual_rank   INTEGER,
    is_allotted       BOOLEAN DEFAULT FALSE,
    physical_room_id  UUID REFERENCES room(id) ON DELETE SET NULL,
    allocated_room_id UUID REFERENCES room(id) ON DELETE SET NULL,
    face_enrolled     BOOLEAN DEFAULT FALSE,
    academic_year     TEXT,
    degree_type       VARCHAR(100),
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, roll_no, degree_type)
);

CREATE TABLE IF NOT EXISTS authority(
    id           TEXT PRIMARY KEY,
    email        VARCHAR(255) UNIQUE NOT NULL,
    password     VARCHAR(255) NOT NULL,
    name         VARCHAR(255) NOT NULL,
    phone        VARCHAR(255) NOT NULL,
    hostel       VARCHAR(255) NOT NULL REFERENCES hostel(name) ON DELETE CASCADE,
    hostel_id    UUID NOT NULL REFERENCES hostel(id) ON DELETE CASCADE,
    approved_by  BOOLEAN DEFAULT false,
    status       VARCHAR(255) DEFAULT 'attendent',
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS guard_devices(
    id               TEXT PRIMARY KEY,
    device_name      VARCHAR(255) DEFAULT 'Main Gate Terminal',
    phone            VARCHAR(255) UNIQUE NOT NULL,
    gate             VARCHAR(100) DEFAULT 'Main Gate',
    activation_code  VARCHAR(50),
    fingerprint_hash TEXT,
    device_info      JSONB,
    device_token     TEXT,
    status           VARCHAR(50) DEFAULT 'PENDING_ACTIVATION',
    approved_by      TEXT REFERENCES authority(id) ON DELETE SET NULL,
    approved_at      TIMESTAMP,
    last_active_at   TIMESTAMP,
    last_ip          VARCHAR(50),
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    guard_type       VARCHAR(20) DEFAULT 'MAIN_GATE' CHECK (guard_type IN ('MAIN_GATE', 'HOSTEL_GATE')),
    hostel_id        UUID REFERENCES hostel(id) ON DELETE SET NULL,
    guard_id         TEXT GENERATED ALWAYS AS (id) STORED
);

ALTER TABLE guard_devices ADD COLUMN IF NOT EXISTS guard_type VARCHAR(20) DEFAULT 'MAIN_GATE' CHECK (guard_type IN ('MAIN_GATE', 'HOSTEL_GATE'));
ALTER TABLE guard_devices ADD COLUMN IF NOT EXISTS hostel_id UUID REFERENCES hostel(id) ON DELETE SET NULL;
ALTER TABLE guard_devices ADD COLUMN IF NOT EXISTS guard_id TEXT GENERATED ALWAYS AS (id) STORED;

CREATE TABLE IF NOT EXISTS guard_device_logs(
    id          TEXT PRIMARY KEY,
    device_id   TEXT REFERENCES guard_devices(id) ON DELETE CASCADE,
    event_type  VARCHAR(50) NOT NULL,
    ip_address  VARCHAR(50),
    details     TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outpass (
    id                 TEXT PRIMARY KEY,
    student_id         TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    outpass_type       VARCHAR(50) NOT NULL CHECK (outpass_type IN ('Home', 'Local', 'Outstation')),
    place_of_visit     VARCHAR(255),
    purpose            TEXT,
    departure_datetime TIMESTAMP,
    arrival_datetime   TIMESTAMP,
    parent_contact     VARCHAR(20) NOT NULL,
    is_active          BOOLEAN DEFAULT TRUE,
    outp_status        VARCHAR(50) DEFAULT 'Pending' CHECK (outp_status IN ('Pending', 'Approved', 'Rejected', 'Cancelled')),
    std_status         VARCHAR(50) DEFAULT 'In' CHECK (std_status IN ('In', 'Out')),
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at        TIMESTAMP,
    approved_by        TEXT REFERENCES authority(id) ON DELETE SET NULL,
    is_emergency       BOOLEAN NOT NULL DEFAULT FALSE,
    hostel_std_status  VARCHAR(50) DEFAULT 'In' CHECK (hostel_std_status IN ('In', 'Out'))
);

ALTER TABLE outpass ADD COLUMN IF NOT EXISTS hostel_std_status VARCHAR(50) DEFAULT 'In' CHECK (hostel_std_status IN ('In', 'Out'));

CREATE TABLE IF NOT EXISTS outpass_remarks (
    id         TEXT PRIMARY KEY,
    outpass_id TEXT NOT NULL REFERENCES outpass(id) ON DELETE CASCADE,
    admin_id   TEXT NOT NULL,
    admin_role VARCHAR(20) NOT NULL CHECK (admin_role IN ('ATTENDANT','CHIEF_WARDEN','GUARD','SYSTEM')),
    remark     TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS otp_verification(
    id          TEXT PRIMARY KEY,
    person_id   TEXT NOT NULL,
    otp         VARCHAR(255) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS guard_action_log (
    id          UUID PRIMARY KEY,
    outpass_id  TEXT NOT NULL REFERENCES outpass(id) ON DELETE CASCADE,
    action      VARCHAR(10) NOT NULL CHECK (action IN ('exit', 'enter')),
    gate        VARCHAR(100) DEFAULT 'Main Gate',
    remark      TEXT,
    actioned_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    guard_id    TEXT REFERENCES guard_devices(id) ON DELETE SET NULL
);

ALTER TABLE guard_action_log ADD COLUMN IF NOT EXISTS guard_id TEXT REFERENCES guard_devices(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS day_scholar (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name        VARCHAR(255) NOT NULL,
    roll_no     VARCHAR(100) NOT NULL,
    degree_type VARCHAR(100),
    phone       VARCHAR(20),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT day_scholar_student_fk
        FOREIGN KEY (name, roll_no, degree_type)
        REFERENCES students(name, roll_no, degree_type)
);

CREATE TABLE IF NOT EXISTS day_scholar_log (
    id             TEXT PRIMARY KEY,
    day_scholar_id TEXT REFERENCES day_scholar(id) ON DELETE CASCADE,
    gate           VARCHAR(255),
    direction      VARCHAR(10) CHECK (direction IN ('ENTRY', 'EXIT')),
    timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_session (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id TEXT NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    role VARCHAR(50),
    login_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP WITH TIME ZONE,
    ip_address VARCHAR(100),
    user_agent TEXT,
    refresh_token_hash TEXT,
    refresh_expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    machine_id VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_user_session_actor_active
ON user_session(actor_id, actor_type, is_active);

CREATE INDEX IF NOT EXISTS idx_user_session_id_active
ON user_session(id, is_active);

CREATE TABLE IF NOT EXISTS visit_log (
    id SERIAL PRIMARY KEY,
    outpass_id TEXT NOT NULL REFERENCES outpass(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    actual_departure TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actual_arrival TIMESTAMP,
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    gate VARCHAR(100) DEFAULT 'Main Gate',
    exit_guard_id TEXT,
    entry_guard_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_visit_log_student ON visit_log(student_id);
CREATE INDEX IF NOT EXISTS idx_visit_log_outpass ON visit_log(outpass_id);

CREATE TABLE IF NOT EXISTS hostel_visit_log (
    id                 TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    outpass_id         TEXT NOT NULL REFERENCES outpass(id) ON DELETE CASCADE,
    student_id         TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    hostel_id          UUID REFERENCES hostel(id) ON DELETE SET NULL,
    hostel_exit_time   TIMESTAMPTZ,
    hostel_entry_time  TIMESTAMPTZ,
    exit_guard_id      TEXT REFERENCES guard_devices(id) ON DELETE SET NULL,
    entry_guard_id     TEXT REFERENCES guard_devices(id) ON DELETE SET NULL,
    remark             TEXT,
    auto_exit          BOOLEAN DEFAULT FALSE,
    created_at         TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hostel_guard_action_log (
    id              TEXT PRIMARY KEY,
    outpass_id      TEXT NOT NULL,
    action          VARCHAR(20) NOT NULL CHECK (action IN ('hostel_exit', 'hostel_enter')),
    gate            VARCHAR(100) DEFAULT 'Hostel Gate',
    remark          TEXT,
    guard_id        TEXT REFERENCES guard_devices(id) ON DELETE SET NULL,
    actioned_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_outpass_hostel_std_status ON outpass(hostel_std_status);
CREATE INDEX IF NOT EXISTS idx_hostel_visit_log_outpass ON hostel_visit_log(outpass_id);
CREATE INDEX IF NOT EXISTS idx_hostel_guard_action_outpass ON hostel_guard_action_log(outpass_id);

