// +build aix

package process

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/internal/common"
	"github.com/DataDog/gopsutil/net"
)

// MemoryMapsStat is a stub for AIX (memory maps not available via /proc).
type MemoryMapsStat struct {
	Path         string `json:"path"`
	Rss          uint64 `json:"rss"`
	Size         uint64 `json:"size"`
	Pss          uint64 `json:"pss"`
	SharedClean  uint64 `json:"sharedClean"`
	SharedDirty  uint64 `json:"sharedDirty"`
	PrivateClean uint64 `json:"privateClean"`
	PrivateDirty uint64 `json:"privateDirty"`
	Referenced   uint64 `json:"referenced"`
	Anonymous    uint64 `json:"anonymous"`
	Swap         uint64 `json:"swap"`
}

// prTimestruc64 mirrors AIX timestruc64_t: { time_t tv_sec; int tv_nsec; int _pad; }
// Total: 16 bytes.
type prTimestruc64 struct {
	Sec  int64
	Nsec int32
	_    uint32
}

// lwpSinfo mirrors AIX lwpsinfo_t (representative LWP info inside psinfo_t).
// Total: 120 bytes.
type lwpSinfo struct {
	LwpID   uint64
	Addr    uint64
	Wchan   uint64
	Flag    uint32
	Wtype   uint8
	State   int8
	Sname   byte   // process state character: 'R','S','Z', etc.
	Nice    uint8
	Pri     int32
	Policy  uint32
	Clname  [8]byte
	Onpro   int32
	Bindpro int32
	Ptid    uint32
	_       uint32
	_       [7]uint64
}

// psinfo mirrors AIX psinfo_t from /usr/include/sys/procfs.h.
// Total: 448 bytes. Fields are big-endian on ppc64.
type psinfo struct {
	Flag   uint32
	Flag2  uint32
	Nlwp   uint32 // number of threads
	_      uint32
	Uid    uint64
	Euid   uint64
	Gid    uint64
	Egid   uint64
	Pid    uint64
	Ppid   uint64
	Pgid   uint64
	Sid    uint64
	Ttydev uint64
	Addr   uint64
	Size   uint64   // virtual memory size in pages
	Rssize uint64   // resident set size in pages
	Start  prTimestruc64
	Time   prTimestruc64 // combined user+system CPU time
	Cid    uint16
	_      uint16
	Argc   uint32
	Argv   uint64
	Envp   uint64
	Fname  [16]byte // executable name, null-terminated (max 15 chars)
	Psargs [80]byte // process args, space-separated, null-terminated (max 79 chars)
	_      [8]uint64
	Lwp    lwpSinfo // representative LWP
}

func readPsinfo(pid int32) (*psinfo, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/psinfo", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var psi psinfo
	if err := binary.Read(f, binary.BigEndian, &psi); err != nil {
		return nil, err
	}
	return &psi, nil
}

func nullTerminatedBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func filledProcessFromPsinfo(psi *psinfo, pid int32, pageSize int) *FilledProcess {
	name := nullTerminatedBytes(psi.Fname[:])
	args := nullTerminatedBytes(psi.Psargs[:])

	var cmdline []string
	if args != "" {
		cmdline = strings.Fields(args)
	}

	cpuSecs := float64(psi.Time.Sec) + float64(psi.Time.Nsec)/1e9

	return &FilledProcess{
		Pid:        pid,
		Ppid:       int32(psi.Ppid),
		Name:       name,
		Cmdline:    cmdline,
		Uids:       []int32{int32(psi.Uid), int32(psi.Euid), int32(psi.Uid), int32(psi.Euid)},
		Gids:       []int32{int32(psi.Gid), int32(psi.Egid), int32(psi.Gid), int32(psi.Egid)},
		MemInfo: &MemoryInfoStat{
			RSS: uint64(psi.Rssize) * uint64(pageSize),
			VMS: uint64(psi.Size) * uint64(pageSize),
		},
		CreateTime: psi.Start.Sec * 1000, // milliseconds since epoch
		CpuTime: cpu.TimesStat{
			CPU:    "cpu",
			User:   cpuSecs, // combined user+sys; split requires root (/proc/<pid>/status)
			System: 0,
		},
		Nice:       int32(int8(psi.Lwp.Nice)),
		NumThreads: int32(psi.Nlwp),
		Status:     string([]byte{psi.Lwp.Sname}),
	}
}

// Pids returns a list of all running process IDs by enumerating /proc.
func Pids() ([]int32, error) {
	dir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	pids := make([]int32, 0, len(names))
	for _, name := range names {
		pid, err := strconv.ParseInt(name, 10, 32)
		if err != nil {
			continue // skip non-numeric entries (e.g. "net", "sys")
		}
		pids = append(pids, int32(pid))
	}
	return pids, nil
}

// NewProcess creates a new Process handle for the given PID.
func NewProcess(pid int32) (*Process, error) {
	// Verify the process exists by checking its psinfo file.
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/psinfo", pid)); err != nil {
		return nil, err
	}
	return &Process{Pid: pid}, nil
}

// AllProcesses returns a map of all running processes keyed by PID.
// It reads /proc/<pid>/psinfo (world-readable, 448 bytes) for each process.
func AllProcesses() (map[int32]*FilledProcess, error) {
	pids, err := Pids()
	if err != nil {
		return nil, fmt.Errorf("aix AllProcesses: could not list pids: %w", err)
	}

	pageSize := os.Getpagesize()
	procs := make(map[int32]*FilledProcess, len(pids))

	for _, pid := range pids {
		psi, err := readPsinfo(pid)
		if err != nil {
			// Process may have exited between Pids() and now; skip it.
			continue
		}
		procs[pid] = filledProcessFromPsinfo(psi, pid, pageSize)
	}
	return procs, nil
}

// --- Process method implementations ---
// Meaningful implementations read psinfo on demand.
// Methods that require root or are not available return ErrNotImplementedError.

func (p *Process) Ppid() (int32, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return 0, err
	}
	return int32(psi.Ppid), nil
}

func (p *Process) Name() (string, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return "", err
	}
	return nullTerminatedBytes(psi.Fname[:]), nil
}

func (p *Process) Exe() (string, error) {
	return "", common.ErrNotImplementedError
}

func (p *Process) Cmdline() (string, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return "", err
	}
	return nullTerminatedBytes(psi.Psargs[:]), nil
}

func (p *Process) CmdlineSlice() ([]string, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return nil, err
	}
	args := nullTerminatedBytes(psi.Psargs[:])
	if args == "" {
		return nil, nil
	}
	return strings.Fields(args), nil
}

func (p *Process) CreateTime() (int64, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return 0, err
	}
	return psi.Start.Sec * 1000, nil
}

func (p *Process) Cwd() (string, error) {
	return "", common.ErrNotImplementedError
}

func (p *Process) Parent() (*Process, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Status() (string, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return "", err
	}
	return string([]byte{psi.Lwp.Sname}), nil
}

func (p *Process) Uids() ([]int32, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return nil, err
	}
	return []int32{int32(psi.Uid), int32(psi.Euid), int32(psi.Uid), int32(psi.Euid)}, nil
}

func (p *Process) Gids() ([]int32, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return nil, err
	}
	return []int32{int32(psi.Gid), int32(psi.Egid), int32(psi.Gid), int32(psi.Egid)}, nil
}

func (p *Process) Terminal() (string, error) {
	return "", common.ErrNotImplementedError
}

func (p *Process) Nice() (int32, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return 0, err
	}
	return int32(int8(psi.Lwp.Nice)), nil
}

func (p *Process) IOnice() (int32, error) {
	return 0, common.ErrNotImplementedError
}

func (p *Process) Rlimit() ([]RlimitStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) IOCounters() (*IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NumCtxSwitches() (*NumCtxSwitchesStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NumFDs() (int32, error) {
	return 0, common.ErrNotImplementedError
}

func (p *Process) NumThreads() (int32, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return 0, err
	}
	return int32(psi.Nlwp), nil
}

func (p *Process) Threads() (map[string]string, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Times() (*cpu.TimesStat, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return nil, err
	}
	cpuSecs := float64(psi.Time.Sec) + float64(psi.Time.Nsec)/1e9
	return &cpu.TimesStat{
		CPU:  "cpu",
		User: cpuSecs,
	}, nil
}

func (p *Process) CPUAffinity() ([]int32, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) MemoryInfo() (*MemoryInfoStat, error) {
	psi, err := readPsinfo(p.Pid)
	if err != nil {
		return nil, err
	}
	pageSize := os.Getpagesize()
	return &MemoryInfoStat{
		RSS: uint64(psi.Rssize) * uint64(pageSize),
		VMS: uint64(psi.Size) * uint64(pageSize),
	}, nil
}

func (p *Process) MemoryInfoEx() (*MemoryInfoExStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Children() ([]*Process, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) OpenFiles() ([]OpenFilesStat, error) {
	return []OpenFilesStat{}, common.ErrNotImplementedError
}

func (p *Process) Connections() ([]net.ConnectionStat, error) {
	return []net.ConnectionStat{}, common.ErrNotImplementedError
}

func (p *Process) NetIOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return []net.IOCountersStat{}, common.ErrNotImplementedError
}

func (p *Process) IsRunning() (bool, error) {
	_, err := os.Stat(fmt.Sprintf("/proc/%d/psinfo", p.Pid))
	return err == nil, nil
}

func (p *Process) MemoryMaps(grouped bool) (*[]MemoryMapsStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) SendSignal(sig syscall.Signal) error {
	return common.ErrNotImplementedError
}

func (p *Process) Suspend() error {
	return common.ErrNotImplementedError
}

func (p *Process) Resume() error {
	return common.ErrNotImplementedError
}

func (p *Process) Terminate() error {
	return common.ErrNotImplementedError
}

func (p *Process) Kill() error {
	return common.ErrNotImplementedError
}

func (p *Process) Username() (string, error) {
	return "", common.ErrNotImplementedError
}
