package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const instanceIndex = "instance"

var (
	errNoNamespace  = errors.New("no stack namespace for this name")
	errAmbiguous    = errors.New("more than one stack namespace has this name")
	errNoSecret     = errors.New("the stack has no access secret yet")
	errNotSynced    = errors.New("the cache is not synced yet")
	errNotStackName = errors.New("the namespace is not a stack namespace")
)

// store caches the stack namespaces and their access Secrets. Every replica
// reads from it; only the leader writes Secrets (through the API, not here).
type store struct {
	namespaces cache.SharedIndexInformer
	secrets    listerscorev1.SecretLister
	secretInf  cache.SharedIndexInformer
	synced     atomic.Bool
	cfg        config
}

// newStore builds the informers. Start them with run.
func newStore(client kubernetes.Interface, cfg config) (*store, error) {
	nsFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.LabelSelector = cfg.NamespaceSelector
		}))
	nsInf := nsFactory.Core().V1().Namespaces().Informer()
	label := cfg.InstanceLabel
	if err := nsInf.AddIndexers(cache.Indexers{
		instanceIndex: func(obj any) ([]string, error) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				return nil, nil
			}
			// Hosts are lower case. k8s-stack-manager still allows older
			// instance names with upper-case letters.
			if v := ns.Labels[label]; v != "" {
				return []string{strings.ToLower(v)}, nil
			}
			return nil, nil
		},
	}); err != nil {
		return nil, fmt.Errorf("add namespace index: %w", err)
	}

	// The RBAC rule names one Secret; the API allows list and watch with that
	// name only through this field selector.
	secFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("metadata.name", cfg.SecretName).String()
		}))
	secInf := secFactory.Core().V1().Secrets()

	return &store{
		namespaces: nsInf,
		secrets:    secInf.Lister(),
		secretInf:  secInf.Informer(),
		cfg:        cfg,
	}, nil
}

// run starts the informers and waits for the first sync. It returns false when
// ctx ended before the caches synced.
func (s *store) run(ctx context.Context) bool {
	go s.namespaces.Run(ctx.Done())
	go s.secretInf.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), s.namespaces.HasSynced, s.secretInf.HasSynced) {
		return false
	}
	s.synced.Store(true)
	return true
}

// onNamespaceChange calls fn for each namespace add or label change.
func (s *store) onNamespaceChange(fn func()) error {
	_, err := s.namespaces.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { fn() },
		UpdateFunc: func(any, any) { fn() },
	})
	return err
}

// onSecretDelete calls fn when an access Secret is deleted, so the leader can
// make it again.
func (s *store) onSecretDelete(fn func()) error {
	_, err := s.secretInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(any) { fn() },
	})
	return err
}

// namespaceForInstance returns the stack namespace with the instance label.
func (s *store) namespaceForInstance(instance string) (*corev1.Namespace, error) {
	if !s.synced.Load() {
		return nil, errNotSynced
	}
	objs, err := s.namespaces.GetIndexer().ByIndex(instanceIndex, strings.ToLower(instance))
	if err != nil {
		return nil, err
	}
	switch len(objs) {
	case 0:
		return nil, errNoNamespace
	case 1:
		ns, ok := objs[0].(*corev1.Namespace)
		if !ok {
			return nil, errNoNamespace
		}
		return ns, nil
	default:
		return nil, errAmbiguous
	}
}

// stackNamespace returns the cached namespace when it is a stack namespace
// whose instance label equals instance.
func (s *store) stackNamespace(name, instance string) (*corev1.Namespace, error) {
	if !s.synced.Load() {
		return nil, errNotSynced
	}
	obj, ok, err := s.namespaces.GetStore().GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNotStackName
	}
	ns, isNS := obj.(*corev1.Namespace)
	if !isNS || ns.Labels[s.cfg.InstanceLabel] != instance || instance == "" {
		return nil, errNotStackName
	}
	return ns, nil
}

// secret returns the cached access Secret of a namespace.
func (s *store) secret(namespace string) (*corev1.Secret, error) {
	if !s.synced.Load() {
		return nil, errNotSynced
	}
	sec, err := s.secrets.Secrets(namespace).Get(s.cfg.SecretName)
	if err != nil {
		return nil, errNoSecret
	}
	return sec, nil
}

// listNamespaces returns all cached stack namespaces.
func (s *store) listNamespaces() []*corev1.Namespace {
	var out []*corev1.Namespace
	for _, obj := range s.namespaces.GetStore().List() {
		if ns, ok := obj.(*corev1.Namespace); ok {
			out = append(out, ns)
		}
	}
	return out
}

// waitSynced blocks until the caches synced or ctx ended.
func (s *store) waitSynced(ctx context.Context) bool {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for !s.synced.Load() {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
	return true
}
