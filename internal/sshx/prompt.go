package sshx

import "context"

// promptHostKey surfaces a TOFU decision to the UI and blocks until the user
// answers or ctx is canceled. A missing Notify callback is treated as a
// cancel so auth can never deadlock waiting for a modal that will never show.
func (m *Manager) promptHostKey(ctx context.Context, hostID, host, keyType, fingerprint string) (bool, error) {
	if !m.hasNotify() {
		return false, ErrCanceled
	}
	// Buffered so the UI's Send never blocks even if we've already given up
	// on ctx cancellation.
	reply := make(chan bool, 1)
	m.notify(HostKeyPromptMsg{
		HostID:      hostID,
		Host:        host,
		KeyType:     keyType,
		Fingerprint: fingerprint,
		Reply:       reply,
	})
	select {
	case ok := <-reply:
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// promptSecret asks the UI for a secret and blocks until answered or ctx is
// canceled. A nil reply (or missing Notify callback) means the user canceled
// authentication and yields ErrCanceled.
func (m *Manager) promptSecret(ctx context.Context, hostID, title, detail string, echo bool) ([]byte, error) {
	if !m.hasNotify() {
		return nil, ErrCanceled
	}
	reply := make(chan []byte, 1)
	m.notify(SecretPromptMsg{
		HostID: hostID,
		Title:  title,
		Detail: detail,
		Echo:   echo,
		Reply:  reply,
	})
	select {
	case secret := <-reply:
		if secret == nil {
			return nil, ErrCanceled
		}
		return secret, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
