// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/api/types/task"
)

func startContainer(ctx context.Context, s *service, c *container) (retErr error) {
	shimLog.WithField("container", c.id).Debug("start container")
	defer func() {
		if retErr != nil {
			// notify the wait goroutine to continue
			c.exitCh <- exitCode255
		}
	}()
	// start a container
	if c.cType == "" {
		err := fmt.Errorf("Bug, the container %s type is empty", c.id)
		return err
	}

	if s.sandbox == nil {
		err := fmt.Errorf("Bug, the sandbox hasn't been created for this container %s", c.id)
		return err
	}

	if c.cType.IsSandbox() {

		shimLog.WithField("container", c.id).Debug("start container IsSandbox")

		err := s.sandbox.Start(ctx)
		if err != nil {
			shimLog.WithField("container", c.id).Debug("start container Error")
			return err
		}
		// Start monitor after starting sandbox
		s.monitor, err = s.sandbox.Monitor(ctx)
		if err != nil {
			shimLog.WithField("container", c.id).Debug("start container Error start monitor")
			return err
		}
		// Split: watching whether we can ping the agent!
		go watchSandbox(ctx, s)

		// We use s.ctx(`ctx` derived from `s.ctx`) to check for cancellation of the
		// shim context and the context passed to startContainer for tracing.
		// RV FIXME: disable watch OOMEvent, until we can support on the kata-proxy service

		// go watchOOMEvents(ctx, s)
	} else {
		shimLog.WithField("container", c.id).Debug("start container: StartContainer")
		_, err := s.sandbox.StartContainer(ctx, c.id)
		if err != nil {
			return err
		}
	}

	// Run post-start OCI hooks.
	/* RV: do need to run post-start hook?
	err := katautils.EnterNetNS(s.sandbox.GetNetNs(), func() error {
		return katautils.PostStartHooks(ctx, *c.spec, s.sandbox.ID(), c.bundle)
	})
	if err != nil {
		// log warning and continue, as defined in oci runtime spec
		// https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle
		shimLog.WithError(err).Warn("Failed to run post-start hooks")
	}
	*/
	c.status = task.StatusRunning

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)
	if err != nil {
		shimLog.WithField("container", c.id).Debug("start container Error IOStream")
		return err
	}

	shimLog.WithFields(logrus.Fields{
		"stdin":  stdin,
		"stdout": stdout,
		"stderr": stderr,
	}).Info("Sandbox IOStream FDs")

	shimLog.WithFields(logrus.Fields{
		"stdin":  c.stdin,
		"stdout": c.stdout,
		"stderr": c.stderr,
	}).Info("Container IOStream FDs")

	if c.cType.IsSandbox() {
		if c.stdin == "" || c.stdout == "" || c.stderr == "" {
			// these are text string
			/*
				c.stdin = stdin
				c.stdout = stdout
				c.stderr = stderr

				shimLog.WithFields(logrus.Fields{
					"stdin":  stdin,
					"stdout": stdout,
					"stderr": stderr,
				}).Info("ReSet Sandbox Container IOStream FDs to SBOX")
			*/

		}
	}

	c.stdinPipe = stdin

	if c.stdin != "" || c.stdout != "" || c.stderr != "" {
		shimLog.WithField("container", c.id).Debug("start container stdin NULL")
		tty, err := newTtyIO(ctx, s.namespace, c.id, c.stdin, c.stdout, c.stderr, c.terminal)
		if err != nil {
			shimLog.WithField("container", c.id).Debug("start container Error tty")
			return err
		}
		c.ttyio = tty

		go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
	} else {
		shimLog.WithField("container", c.id).Debug("start container Close")
		// close the io exit channel, since there is no io for this container,
		// otherwise the following wait goroutine will hang on this channel.
		close(c.exitIOch)
		// close the stdin closer channel to notify that it's safe to close process's
		// io.
		close(c.stdinCloser)
	}

	go wait(ctx, s, c, "")

	return nil
}

func startExec(ctx context.Context, s *service, containerID, execID string) (e *exec, retErr error) {
	shimLog.WithFields(logrus.Fields{
		"container": containerID,
		"exec":      execID,
	}).Debug("start container execution")
	// start an exec
	c, err := s.getContainer(containerID)
	if err != nil {
		return nil, err
	}

	execs, err := c.getExec(execID)
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			// notify the wait goroutine to continue
			execs.exitCh <- exitCode255
		}
	}()

	_, proc, err := s.sandbox.EnterContainer(ctx, containerID, *execs.cmds)
	if err != nil {
		err := fmt.Errorf("cannot enter container %s, with err %s", containerID, err)
		return nil, err
	}
	execs.id = proc.Token

	execs.status = task.StatusRunning
	if execs.tty.height != 0 && execs.tty.width != 0 {
		err = s.sandbox.WinsizeProcess(ctx, c.id, execs.id, execs.tty.height, execs.tty.width)
		if err != nil {
			return nil, err
		}
	}

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, execs.id)
	if err != nil {
		return nil, err
	}

	execs.stdinPipe = stdin

	tty, err := newTtyIO(ctx, s.namespace, execs.id, execs.tty.stdin, execs.tty.stdout, execs.tty.stderr, execs.tty.terminal)
	if err != nil {
		return nil, err
	}
	execs.ttyio = tty

	go ioCopy(shimLog.WithFields(logrus.Fields{
		"container": c.id,
		"exec":      execID,
	}), execs.exitIOch, execs.stdinCloser, tty, stdin, stdout, stderr)

	go wait(ctx, s, c, execID)

	return execs, nil
}
