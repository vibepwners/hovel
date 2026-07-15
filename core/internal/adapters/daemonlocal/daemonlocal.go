package daemonlocal

import (
	"context"
	"errors"
	"net/http"

	"github.com/vibepwners/hovel/internal/adapters/daemonrpc"
	"github.com/vibepwners/hovel/internal/adapters/storage/filesystem"
	sqlitestore "github.com/vibepwners/hovel/internal/adapters/storage/sqlite"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/infra/daemonmanager"
	"github.com/vibepwners/hovel/internal/infra/daemonruntime"
	"github.com/vibepwners/hovel/internal/moduleruntime/pythonrpc"
)

func NewManager() daemonmanager.Manager {
	store := filesystem.NewWorkspaceStore()
	return daemonmanager.New(store, SocketReachable, EndpointNetwork, Serve)
}

func Serve(ctx context.Context, args daemonruntime.Args) error {
	return daemonruntime.Serve(ctx, WithDefaults(args))
}

func WithDefaults(args daemonruntime.Args) daemonruntime.Args {
	if args.ParseEndpoint == nil {
		args.ParseEndpoint = ParseEndpoint
	}
	if args.Store == nil {
		args.Store = filesystem.NewWorkspaceStore()
	}
	if args.AcquireWorkspaceLock == nil {
		args.AcquireWorkspaceLock = func(workspacePath, owner string) (daemonruntime.WorkspaceLock, error) {
			return filesystem.AcquireWorkspaceLock(workspacePath, owner)
		}
	}
	if args.NewEventSink == nil {
		args.NewEventSink = func(workspacePath string) services.EventSink {
			return sqlitestore.NewStore(workspacePath)
		}
	}
	if args.NewLogPublisher == nil {
		args.NewLogPublisher = func() daemonruntime.LogPublisher {
			return daemonrpc.NewLogBroker()
		}
	}
	if args.NewRPCServer == nil {
		args.NewRPCServer = NewRPCServer
	}
	if args.NewModuleRuntime == nil {
		args.NewModuleRuntime = NewModuleRuntime
	}
	if args.NewPKIControl == nil {
		if args.PKIBackends == nil && args.PKIValidators == nil {
			args.NewPKIControl = newWorkspacePKIControl
		} else {
			backends := args.PKIBackends
			validators := args.PKIValidators
			args.NewPKIControl = func(ctx context.Context, workspacePath string) (apppki.WorkspaceControl, error) {
				return newWorkspacePKIControlWithRegistries(
					ctx, workspacePath, backends, validators,
				)
			}
		}
	}
	return args
}

func ParseEndpoint(value string) (daemonruntime.Endpoint, error) {
	endpoint, err := daemonrpc.ParseEndpoint(value)
	if err != nil {
		return daemonruntime.Endpoint{}, err
	}
	return daemonruntime.Endpoint{
		Network: endpoint.Network,
		Address: endpoint.Address,
		Display: endpoint.String(),
	}, nil
}

func EndpointNetwork(value string) (string, bool) {
	endpoint, err := daemonrpc.ParseEndpoint(value)
	if err != nil {
		return "", false
	}
	return endpoint.Network, true
}

func SocketReachable(ctx context.Context, socketPath string) bool {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return false
	}
	defer func() { logDaemonLocalError("close daemon health-check client", client.Close()) }()
	_, err = client.PollLogs(ctx, 0)
	return err == nil
}

func NewRPCServer(config daemonruntime.RPCServerConfig) (http.Handler, error) {
	logs, ok := config.Logs.(*daemonrpc.LogBroker)
	if !ok {
		return nil, errors.New("daemon local rpc server requires daemonrpc log broker")
	}
	return daemonrpc.NewHandler(
		config.Runs,
		daemonrpc.WithSession(config.Session),
		daemonrpc.WithLogBroker(logs),
		daemonrpc.WithSessionPersistence(config.PersistSession),
		daemonrpc.WithModuleSessions(config.ModuleSessions),
		daemonrpc.WithLaunchKeyPolicy(config.LaunchKeyPolicy),
		daemonrpc.WithPKIControl(config.PKI),
		daemonrpc.WithPKISecretResponses(config.Confidential),
		daemonrpc.WithPrivilegedControl(config.Confidential),
	)
}

func NewModuleRuntime(config daemonruntime.ModuleRuntimeConfig) (services.ModuleRunner, services.SessionBroker) {
	sessions := pythonrpc.NewSessionBroker()
	return pythonrpc.Runner{
		ConfigPath:           config.ModuleConfig,
		HovelConfig:          config.HovelConfig,
		WorkspacePath:        config.WorkspacePath,
		Events:               config.Events,
		IDs:                  config.IDs,
		Clock:                config.Clock,
		Sessions:             sessions,
		CredentialExecutions: config.CredentialExecutions,
	}, sessions
}
