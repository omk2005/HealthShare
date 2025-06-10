'use strict';

const { Contract } = require('fabric-contract-api');

// ABAC utility class
class ABAC {
  static requireRole(ctx, expectedRoles) {
    const role = ctx.clientIdentity.getAttributeValue('role');
    if (!role || !expectedRoles.includes(role)) {
      throw new Error(`Access denied: ${expectedRoles.join(' or ')} role required, but found ${role || 'none'}`);
    }
    return role;
  }

  static getAttr(ctx, attr, defaultValue = null) {
    const val = ctx.clientIdentity.getAttributeValue(attr);
    if (val === null && defaultValue === null) throw new Error(`Missing required attribute: ${attr}`);
    return val !== null ? val : defaultValue;
  }

  static assertEquals(actual, expected, message) {
    if (actual !== expected) throw new Error(message);
  }
}

// BaseContract for common utilities
class BaseContract extends Contract {
  // Generic read helper
  async _readState(ctx, key) {
    const data = await ctx.stub.getState(key);
    if (!data || data.length === 0) {
      throw new Error(`State ${key} does not exist`);
    }
    return data.toString();
  }

  // Generic write helper
  async _writeState(ctx, key, jsonData) {
    await ctx.stub.putState(key, Buffer.from(jsonData));
  }

  // Log actions to the audit-channel
  async _logAudit(ctx, action, details) {
    if (ctx.stub.getChannelID() === 'audit-channel') {
      const ts = ctx.stub.getTxTimestamp();
      if (!ts || !ts.seconds) {
        throw new Error('Failed to get transaction timestamp');
      }
      const auditKey = ctx.stub.createCompositeKey('audit', [ctx.stub.getTxID()]);
      const auditData = {
        timestamp: ts.seconds.low,
        user: ctx.clientIdentity.getID(),
        channel: ctx.stub.getChannelID(),
        action,
        details
      };
      await ctx.stub.putState(auditKey, Buffer.from(JSON.stringify(auditData)));
    }
  }

  // Validate access based on policy
  async _checkAccessPolicy(ctx, patientId, dataType, permission) {
    const callerRole = ABAC.getAttr(ctx, 'role');
    const callerId = ctx.clientIdentity.getID();
    const callerHospitalID = ABAC.getAttr(ctx, 'hospitalID');
    const iterator = await ctx.stub.getStateByPartialCompositeKey('policy', [patientId, callerRole, dataType]);
    let hasAccess = false;
    let record;

    while (true) {
      const res = await iterator.next();
      if (res.value) {
        const policy = JSON.parse(res.value.value.toString());
        if (policy.permissions.includes(permission) && (!policy.expiry || policy.expiry > Date.now())) {
          hasAccess = true;
          const recordKey = ctx.stub.createCompositeKey(dataType, [patientId]);
          const recordJson = await this._readState(ctx, recordKey);
          record = JSON.parse(recordJson);
          ABAC.assertEquals(record.hospitalID, callerHospitalID, 'Access denied: Record belongs to a different hospital');
          const clearance = ABAC.getAttr(ctx, 'clearance', 'low');
          if (record.sensitivity === 'high' && clearance !== 'high') {
            throw new Error('Access denied: High sensitivity data requires high clearance');
          }
          break;
        }
      }
      if (res.done) {
        await iterator.close();
        break;
      }
    }

    if (!hasAccess) {
      throw new Error(`Access denied: No ${permission} access for ${callerRole} ${callerId} on ${dataType} for patient ${patientId}`);
    }
    return record;
  }
}

// AdminContract for managing users
class AdminContract extends BaseContract {
  constructor() {
    super('AdminContract');
  }

  async createPatient(ctx, patientId, hospitalID, patientDataJson) {
    ABAC.requireRole(ctx, ['admin']);
    const adminHospitalID = ABAC.getAttr(ctx, 'hospitalID');
    ABAC.assertEquals(adminHospitalID, hospitalID, 'Access denied: Admin can only create patients in their hospital');

    const ehrKey = ctx.stub.createCompositeKey('ehr', [patientId]);
    const exists = await ctx.stub.getState(ehrKey);
    if (exists && exists.length > 0) {
      throw new Error(`Patient ${patientId} already exists`);
    }

    const patientData = JSON.parse(patientDataJson);
    patientData.hospitalID = hospitalID;
    patientData.sensitivity = patientData.sensitivity || 'low';

    await this._writeState(ctx, ehrKey, JSON.stringify(patientData));
    await this._logAudit(ctx, 'createPatient', { patientId, hospitalID });
    return { success: `Patient ${patientId} created` };
  }

  async deletePatient(ctx, patientId) {
    ABAC.requireRole(ctx, ['admin']);
    const adminHospitalID = ABAC.getAttr(ctx, 'hospitalID');

    const ehrKey = ctx.stub.createCompositeKey('ehr', [patientId]);
    const recordJson = await this._readState(ctx, ehrKey);
    const record = JSON.parse(recordJson);
    ABAC.assertEquals(record.hospitalID, adminHospitalID, 'Access denied: Patient belongs to a different hospital');

    await ctx.stub.deleteState(ehrKey);
    await this._logAudit(ctx, 'deletePatient', { patientId });
    return { success: `Patient ${patientId} deleted` };
  }

  async getAllPatients(ctx) {
    ABAC.requireRole(ctx, ['admin']);
    const adminHospitalID = ABAC.getAttr(ctx, 'hospitalID');

    const iterator = await ctx.stub.getStateByPartialCompositeKey('ehr', []);
    const results = [];
    while (true) {
      const res = await iterator.next();
      if (res.value && res.value.value.toString()) {
        const record = JSON.parse(res.value.value.toString());
        if (record.hospitalID === adminHospitalID) {
          results.push(record);
        }
      }
      if (res.done) {
        await iterator.close();
        break;
      }
    }
    await this._logAudit(ctx, 'getAllPatients', { count: results.length });
    return JSON.stringify(results);
  }
}

// PatientContract for managing own data and access
class PatientContract extends BaseContract {
  constructor() {
    super('PatientContract');
  }

  async readMyRecord(ctx, patientId, dataType) {
    ABAC.requireRole(ctx, ['patient']);
    const callerId = ctx.clientIdentity.getID();
    if (!callerId.includes(patientId)) {
      throw new Error('Access denied: Can only read your own record');
    }

    const recordKey = ctx.stub.createCompositeKey(dataType, [patientId]);
    const recordJson = await this._readState(ctx, recordKey);
    await this._logAudit(ctx, 'readMyRecord', { patientId, dataType });
    return recordJson;
  }

  async updateMyRecord(ctx, patientId, dataType, updatedDataJson) {
    ABAC.requireRole(ctx, ['patient']);
    const callerId = ctx.clientIdentity.getID();
    if (!callerId.includes(patientId)) {
      throw new Error('Access denied: Can only update your own record');
    }

    const recordKey = ctx.stub.createCompositeKey(dataType, [patientId]);
    const recordJson = await this._readState(ctx, recordKey);
    const existingRecord = JSON.parse(recordJson);
    const updatedData = JSON.parse(updatedDataJson);
    updatedData.hospitalID = existingRecord.hospitalID;
    updatedData.sensitivity = updatedData.sensitivity || existingRecord.sensitivity;

    await this._writeState(ctx, recordKey, JSON.stringify(updatedData));
    await this._logAudit(ctx, 'updateMyRecord', { patientId, dataType });
    return { success: `${dataType} for patient ${patientId} updated` };
  }

  async grantAccess(ctx, patientId, role, dataType, permissions, expiry) {
    ABAC.requireRole(ctx, ['patient']);
    const callerId = ctx.clientIdentity.getID();
    if (!callerId.includes(patientId)) {
      throw new Error('Access denied: Can only grant access for your own record');
    }

    const validPermissions = ['read', 'write'];
    const permissionArray = permissions.split(',').map(p => p.trim());
    if (!permissionArray.every(p => validPermissions.includes(p))) {
      throw new Error('Invalid permissions: Only "read" and "write" are allowed');
    }

    const policy = {
      patientId,
      role,
      dataType,
      permissions: permissionArray,
      expiry: expiry ? parseInt(expiry) : null
    };
    const policyKey = ctx.stub.createCompositeKey('policy', [patientId, role, dataType]);
    await this._writeState(ctx, policyKey, JSON.stringify(policy));
    await this._logAudit(ctx, 'grantAccess', { patientId, role, dataType, permissions, expiry });
    return { success: `Access policy created for ${role} on ${dataType}` };
  }

  async revokeAccess(ctx, patientId, role, dataType) {
    ABAC.requireRole(ctx, ['patient']);
    const callerId = ctx.clientIdentity.getID();
    if (!callerId.includes(patientId)) {
      throw new Error('Access denied: Can only revoke access for your own record');
    }

    const policyKey = ctx.stub.createCompositeKey('policy', [patientId, role, dataType]);
    const policyJson = await this._readState(ctx, policyKey);
    await ctx.stub.deleteState(policyKey);
    await this._logAudit(ctx, 'revokeAccess', { patientId, role, dataType });
    return { success: `Access policy for ${role} on ${dataType} revoked` };
  }
}

// DoctorContract for managing patient records
class DoctorContract extends BaseContract {
  constructor() {
    super('DoctorContract');
  }

  async readPatientRecord(ctx, patientId, dataType) {
    ABAC.requireRole(ctx, ['doctor']);
    const record = await this._checkAccessPolicy(ctx, patientId, dataType, 'read');
    await this._logAudit(ctx, 'readPatientRecord', { patientId, dataType, doctorId: ctx.clientIdentity.getID() });
    return JSON.stringify(record);
  }

  async updatePatientRecord(ctx, patientId, dataType, updatedDataJson) {
    ABAC.requireRole(ctx, ['doctor']);
    const recordKey = ctx.stub.createCompositeKey(dataType, [patientId]);
    const existingRecord = await this._checkAccessPolicy(ctx, patientId, dataType, 'write');
    const updatedData = JSON.parse(updatedDataJson);

    const mergedRecord = { ...existingRecord, medical: updatedData.medical || existingRecord.medical };
    mergedRecord.hospitalID = existingRecord.hospitalID;
    mergedRecord.sensitivity = mergedRecord.sensitivity || existingRecord.sensitivity;

    await this._writeState(ctx, recordKey, JSON.stringify(mergedRecord));
    await this._logAudit(ctx, 'updatePatientRecord', { patientId, dataType, doctorId: ctx.clientIdentity.getID() });
    return { success: `${dataType} for patient ${patientId} updated` };
  }

  async createLabReport(ctx, patientId, labId, labDataJson) {
    ABAC.requireRole(ctx, ['doctor']);
    await this._checkAccessPolicy(ctx, patientId, 'ehr', 'write');
    const hospitalID = ABAC.getAttr(ctx, 'hospitalID');

    const labKey = ctx.stub.createCompositeKey('lab', [patientId, labId]);
    const exists = await ctx.stub.getState(labKey);
    if (exists && exists.length > 0) {
      throw new Error(`Lab report ${labId} for patient ${patientId} already exists`);
    }

    const labData = JSON.parse(labDataJson);
    labData.hospitalID = hospitalID;
    labData.sensitivity = labData.sensitivity || 'medium';

    await this._writeState(ctx, labKey, JSON.stringify(labData));
    await this._logAudit(ctx, 'createLabReport', { patientId, labId, doctorId: ctx.clientIdentity.getID() });
    return { success: `Lab report ${labId} created for patient ${patientId}` };
  }

  async createPrescription(ctx, patientId, prescriptionId, prescriptionDataJson) {
    ABAC.requireRole(ctx, ['doctor']);
    await this._checkAccessPolicy(ctx, patientId, 'ehr', 'write');
    const hospitalID = ABAC.getAttr(ctx, 'hospitalID');

    const prescriptionKey = ctx.stub.createCompositeKey('prescription', [patientId, prescriptionId]);
    const exists = await ctx.stub.getState(prescriptionKey);
    if (exists && exists.length > 0) {
      throw new Error(`Prescription ${prescriptionId} for patient ${patientId} already exists`);
    }

    const prescriptionData = JSON.parse(prescriptionDataJson);
    prescriptionData.hospitalID = hospitalID;
    prescriptionData.sensitivity = prescriptionData.sensitivity || 'low';

    await this._writeState(ctx, prescriptionKey, JSON.stringify(prescriptionData));
    await this._logAudit(ctx, 'createPrescription', { patientId, prescriptionId, doctorId: ctx.clientIdentity.getID() });
    return { success: `Prescription ${prescriptionId} created for patient ${patientId}` };
  }
}

// NurseContract for read-only access
class NurseContract extends BaseContract {
  constructor() {
    super('NurseContract');
  }

  async readPatientRecord(ctx, patientId, dataType) {
    ABAC.requireRole(ctx, ['nurse']);
    const recordKey = ctx.stub.createCompositeKey(dataType, [patientId]);
    const recordJson = await this._readState(ctx, recordKey);
    const record = JSON.parse(recordJson);

    const callerHospitalID = ABAC.getAttr(ctx, 'hospitalID');
    ABAC.assertEquals(record.hospitalID, callerHospitalID, 'Access denied: Record belongs to a different hospital');
    const clearance = ABAC.getAttr(ctx, 'clearance', 'low');
    if (record.sensitivity === 'high' && clearance !== 'high') {
      throw new Error('Access denied: High sensitivity data requires high clearance');
    }

    await this._logAudit(ctx, 'readPatientRecord', { patientId, dataType, nurseId: ctx.clientIdentity.getID() });
    return JSON.stringify(record);
  }
}

// InsuranceContract for insurance-related data
class InsuranceContract extends BaseContract {
  constructor() {
    super('InsuranceContract');
  }

  async readInsuranceData(ctx, patientId) {
    ABAC.requireRole(ctx, ['insurance']);
    if (ctx.stub.getChannelID() !== 'insurance-channel') {
      throw new Error('Access denied: Insurance data only accessible on insurance-channel');
    }
    const record = await this._checkAccessPolicy(ctx, patientId, 'insurance', 'read');
    await this._logAudit(ctx, 'readInsuranceData', { patientId, insuranceId: ctx.clientIdentity.getID() });
    return JSON.stringify(record);
  }

  async updateInsuranceData(ctx, patientId, insuranceDataJson) {
    ABAC.requireRole(ctx, ['insurance']);
    if (ctx.stub.getChannelID() !== 'insurance-channel') {
      throw new Error('Access denied: Insurance data only accessible on insurance-channel');
    }
    const recordKey = ctx.stub.createCompositeKey('insurance', [patientId]);
    const existingRecord = await this._checkAccessPolicy(ctx, patientId, 'insurance', 'write');
    const updatedData = JSON.parse(insuranceDataJson);

    const mergedRecord = { ...existingRecord, policy: updatedData.policy || existingRecord.policy };
    mergedRecord.hospitalID = existingRecord.hospitalID;
    mergedRecord.sensitivity = mergedRecord.sensitivity || existingRecord.sensitivity;

    await this._writeState(ctx, recordKey, JSON.stringify(mergedRecord));
    await this._logAudit(ctx, 'updateInsuranceData', { patientId, insuranceId: ctx.clientIdentity.getID() });
    return { success: `Insurance data for patient ${patientId} updated` };
  }
}

// AuditContract for querying audit logs
class AuditContract extends BaseContract {
  constructor() {
    super('AuditContract');
  }

  async getAuditLogs(ctx, startTime, endTime) {
    ABAC.requireRole(ctx, ['admin', 'patient']);
    if (ctx.stub.getChannelID() !== 'audit-channel') {
      throw new Error('Access denied: Audit logs only accessible on audit-channel');
    }

    const iterator = await ctx.stub.getStateByPartialCompositeKey('audit', []);
    const results = [];
    const start = parseInt(startTime) || 0;
    const end = parseInt(endTime) || Date.now();

    while (true) {
      const res = await iterator.next();
      if (res.value && res.value.value.toString()) {
        const log = JSON.parse(res.value.value.toString());
        if (log.timestamp >= start && log.timestamp <= end) {
          const role = ABAC.getAttr(ctx, 'role');
          if (role === 'admin' || (log.details.patientId && ctx.clientIdentity.getID().includes(log.details.patientId))) {
            results.push(log);
          }
        }
      }
      if (res.done) {
        await iterator.close();
        break;
      }
    }
    return JSON.stringify(results);
  }
}

module.exports.contracts = [
  AdminContract,
  PatientContract,
  DoctorContract,
  NurseContract,
  InsuranceContract,
  AuditContract
];
