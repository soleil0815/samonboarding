"""Pydantic-Modelle fuer die Anfragen der API."""

from pydantic import BaseModel


class LoginModel(BaseModel):
    username: str
    password: str


class SmtpConfigModel(BaseModel):
    enabled: bool
    displayName: str
    host: str
    port: int
    username: str
    password: str
    fromEmail: str
    ccRecipients: str
    tlsMode: str
    notifyOffboarding: bool
    notifyPwdReset: bool
    notifyUserMgmt: bool
    notifyDeletion: bool = False


class OffboardingConfigModel(BaseModel):
    sourceOus: list[str]
    targetOu: str


class ExchangeConfigModel(BaseModel):
    enabled: bool = False
    server: str = ""
    port: int = 443
    ssl: bool = True
    verifyCert: bool = True
    auth: str = "negotiate"
    database: str = ""
    domainController: str = ""


class PwdResetConfigModel(BaseModel):
    sourceOus: list[str]


class UserMgmtConfigModel(BaseModel):
    sourceOus: list[str]
    targetOus: list[str]
    groupOus: list[str]


class DeletionLocationModel(BaseModel):
    enabled: bool = False
    roots: list[str] = []
    useAdAttr: bool = True
    suffixes: list[str] = []
    takeOwnership: bool = False


class DeletionConfigModel(BaseModel):
    enabled: bool
    disabledOu: str
    profile: DeletionLocationModel
    folderRedirection: DeletionLocationModel
    home: DeletionLocationModel


class DeletionSimulateModel(BaseModel):
    userDn: str


class DeletionExecuteModel(BaseModel):
    userDn: str
    planId: str
    confirmSam: str
    password: str = ""


class DeletionBatchSimulateModel(BaseModel):
    userDns: list[str]


class DeletionBatchExecuteModel(BaseModel):
    planId: str
    confirmCount: int
    password: str = ""


class OffboardActionModel(BaseModel):
    userDn: str


class RestoreModel(BaseModel):
    targetOu: str = ""


class OffboardBatchModel(BaseModel):
    userDns: list[str]


class PwdResetActionModel(BaseModel):
    userDn: str
    mode: str
    newPassword: str
    forceChange: bool
    unlockAccount: bool


class MoveUserActionModel(BaseModel):
    userDn: str
    targetOu: str


class UpdateUserGroupsModel(BaseModel):
    userDn: str
    addGroupDns: list[str]
    removeGroupDns: list[str]


class OnboardModel(BaseModel):
    firstName: str
    lastName: str
    templateId: int
    customMail: str = ""


def clean_ou_list(values):
    out, seen = [], set()
    for value in values:
        ou = str(value).strip()
        if ou and ou.lower() not in seen:
            seen.add(ou.lower())
            out.append(ou)
    return out


class ReportsDeleteModel(BaseModel):
    kind: str  # "audit" (Aenderungen) oder "log" (Protokoll)
    olderThanDays: int = 0  # 0 = alle Eintraege
    password: str = ""


class CertUploadModel(BaseModel):
    # Dateiinhalte Base64-kodiert: entweder pfx (+ password) oder cert + key (+ chain, password fuer den Schluessel)
    pfx: str = ""
    cert: str = ""
    key: str = ""
    chain: str = ""
    password: str = ""


class CertSelfSignedModel(BaseModel):
    names: list[str] = []
