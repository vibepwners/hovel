package daemonrpc

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

const serviceName = "Daemon"

type RunMockExploitRequest struct {
	ModuleID string
	Target   string
}

type Finding struct {
	Title    string
	Severity string
	Detail   string
}

type Artifact struct {
	Name string
	Kind string
	Data string
}

type RunMockExploitResponse struct {
	RunID     string
	ModuleID  string
	Target    string
	State     string
	Summary   string
	Findings  []Finding
	Artifacts []Artifact
}

type Server struct {
	runs services.RunService
}

func Register(server *rpc.Server, runs services.RunService) error {
	return server.RegisterName(serviceName, Server{runs: runs})
}

func (s Server) RunMockExploit(req RunMockExploitRequest, resp *RunMockExploitResponse) error {
	result, err := s.runs.ExecuteMockExploit(context.Background(), services.ExecuteMockExploitRequest{
		ModuleID: req.ModuleID,
		Target:   req.Target,
	})
	if err != nil {
		return err
	}
	*resp = responseFromResult(result)
	return nil
}

type Client struct {
	rpc *rpc.Client
}

func Dial(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

func NewClient(conn net.Conn) *Client {
	return &Client{rpc: jsonrpc.NewClient(conn)}
}

func (c *Client) Close() error {
	return c.rpc.Close()
}

func (c *Client) RunMockExploit(ctx context.Context, req RunMockExploitRequest) (RunMockExploitResponse, error) {
	var resp RunMockExploitResponse
	done := make(chan error, 1)
	go func() {
		done <- c.rpc.Call(serviceName+".RunMockExploit", req, &resp)
	}()

	select {
	case <-ctx.Done():
		_ = c.Close()
		return RunMockExploitResponse{}, ctx.Err()
	case err := <-done:
		return resp, err
	}
}

func responseFromResult(result run.Result) RunMockExploitResponse {
	resp := RunMockExploitResponse{
		RunID:    result.ID,
		ModuleID: result.ModuleID,
		Target:   result.Target,
		State:    string(result.State),
		Summary:  result.Summary,
	}
	for _, finding := range result.Findings {
		resp.Findings = append(resp.Findings, Finding{
			Title:    finding.Title,
			Severity: string(finding.Severity),
			Detail:   finding.Detail,
		})
	}
	for _, artifact := range result.Artifacts {
		resp.Artifacts = append(resp.Artifacts, Artifact{
			Name: artifact.Name,
			Kind: artifact.Kind,
			Data: artifact.Data,
		})
	}
	return resp
}
