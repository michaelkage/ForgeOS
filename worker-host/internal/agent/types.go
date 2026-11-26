package agent

import "time"

type Resources struct {
	CPUCores int `json:"cpuCores"`
	MemoryMiB int `json:"memoryMiB"`
	DiskGiB int `json:"diskGiB"`
	ProcessLimit int `json:"processLimit"`
	WallTimeSeconds int `json:"wallTimeSeconds"`
}

type ProvisionRequest struct {
	RequestID string `json:"requestId"`
	JobID string `json:"jobId"`
	Attempt int `json:"attempt"`
	Architecture string `json:"architecture"`
	ROMBase string `json:"romBase"`
	ImageDigest string `json:"imageDigest"`
	Resources Resources `json:"resources"`
	EgressPolicyID string `json:"egressPolicyId"`
	BootstrapCredential string `json:"bootstrapCredential"`
}

type Instance struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	JobID string `json:"jobId"`
	Attempt int `json:"attempt"`
	Architecture string `json:"architecture"`
	ImageDigest string `json:"imageDigest"`
	CreatedAt time.Time `json:"createdAt"`
}

type IsolationProfile struct {
	FirecrackerMicroVM bool `json:"firecrackerMicroVm"`
	DedicatedKernel bool `json:"dedicatedKernel"`
	Jailer bool `json:"jailer"`
	NonRootVMM bool `json:"nonRootVmm"`
	NoHostMounts bool `json:"noHostMounts"`
	NoContainerSocket bool `json:"noContainerSocket"`
	NoHostPIDNamespace bool `json:"noHostPidNamespace"`
	EncryptedEphemeralDisk bool `json:"encryptedEphemeralDisk"`
	HardCPULimit bool `json:"hardCpuLimit"`
	HardMemoryLimit bool `json:"hardMemoryLimit"`
	HardDiskLimit bool `json:"hardDiskLimit"`
	HardProcessLimit bool `json:"hardProcessLimit"`
	WallTimeLimit bool `json:"wallTimeLimit"`
	EgressFiltering bool `json:"egressFiltering"`
	MetadataBlocked bool `json:"metadataBlocked"`
	DestroyAfterJob bool `json:"destroyAfterJob"`
	EgressPolicyID string `json:"egressPolicyId"`
	Resources Resources `json:"resources"`
}

type AttestationPayload struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	JobID string `json:"jobId"`
	Attempt int `json:"attempt"`
	Architecture string `json:"architecture"`
	ImageDigest string `json:"imageDigest"`
	RequestNonce string `json:"requestNonce"`
	IsolationProfile IsolationProfile `json:"isolationProfile"`
	IssuedAt time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type SignedAttestation struct {
	Payload AttestationPayload `json:"payload"`
	Signature string `json:"signature"`
}

type ProvisionResponse struct {
	Instance Instance `json:"instance"`
	Attestation SignedAttestation `json:"attestation"`
}

type StatePayload struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	State string `json:"state"`
	ObservedAt time.Time `json:"observedAt"`
}

type StateResponse struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	State string `json:"state"`
	ObservedAt time.Time `json:"observedAt"`
	Signature string `json:"signature"`
}

type TerminatePayload struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	Accepted bool `json:"accepted"`
	RequestID string `json:"requestId"`
}

type TerminateResponse struct {
	Provider string `json:"provider"`
	InstanceID string `json:"instanceId"`
	Accepted bool `json:"accepted"`
	RequestID string `json:"requestId"`
	Signature string `json:"signature"`
}
