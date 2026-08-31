package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

const (
	statusRPCTimeout  = 5 * time.Second
	applyRPCTimeout   = 15 * time.Second
	restartRPCTimeout = 30 * time.Second
)

func getStatus(ctx context.Context, socketPath, interfaceName string) (*controlapiv1.InterfaceStatus, error) {
	return getInterfaceStatus(ctx, socketPath, interfaceName, false)
}

func getStatusWithSecrets(ctx context.Context, socketPath, interfaceName string) (*controlapiv1.InterfaceStatus, error) {
	return getInterfaceStatus(ctx, socketPath, interfaceName, true)
}

func getInterfaceStatus(ctx context.Context, socketPath, interfaceName string, includeSecrets bool) (*controlapiv1.InterfaceStatus, error) {
	client, err := controlapi.DialUnix(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	rpcCtx, cancel := context.WithTimeout(ctx, statusRPCTimeout)
	defer cancel()
	target := controlapiv1.InterfaceRef_builder{}.Build()
	target.SetInterfaceName(interfaceName)
	request := controlapiv1.GetInterfaceRequest_builder{Target: target}.Build()
	request.SetIncludeSecrets(includeSecrets)
	response, err := client.GetInterface(rpcCtx, request)
	if err != nil {
		return nil, err
	}
	status := response.GetStatus()
	if status == nil {
		return nil, errors.New("controlapi: GetInterface returned no status")
	}
	return status, nil
}

func listInterfaceStatuses(ctx context.Context, socketPath string) ([]*controlapiv1.InterfaceStatus, error) {
	client, err := controlapi.DialUnix(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	rpcCtx, cancel := context.WithTimeout(ctx, statusRPCTimeout)
	defer cancel()
	response, err := client.ListInterfaces(rpcCtx, controlapiv1.ListInterfacesRequest_builder{}.Build())
	if err != nil {
		return nil, err
	}
	return response.GetInterfaces(), nil
}

func applyPeers(ctx context.Context, socketPath string, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	client, err := controlapi.DialUnix(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	rpcCtx, cancel := context.WithTimeout(ctx, applyRPCTimeout)
	defer cancel()
	response, err := client.ApplyPeers(rpcCtx, request)
	if err != nil {
		return nil, fmt.Errorf("controlapi: apply peers: %w", err)
	}
	return response, nil
}

func restartInterface(ctx context.Context, socketPath string, request *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	client, err := controlapi.DialUnix(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	rpcCtx, cancel := context.WithTimeout(ctx, restartRPCTimeout)
	defer cancel()
	response, err := client.RestartInterface(rpcCtx, request)
	if err != nil {
		return nil, fmt.Errorf("controlapi: restart interface: %w", err)
	}
	return response, nil
}
