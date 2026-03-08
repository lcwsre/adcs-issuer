package v1

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var clusteradcsissuerlog = logf.Log.WithName("clusteradcsissuer-resource")

func (r *ClusterAdcsIssuer) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-adcs-certmanager-lcwsre-io-v1-clusteradcsissuer,mutating=true,failurePolicy=fail,groups=adcs.certmanager.lcwsre.io,resources=clusteradcsissuers,verbs=create;update,versions=v1,name=mclusteradcsissuer.adcs.certmanager.lcwsre.io,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Defaulter = &ClusterAdcsIssuer{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) Default() {
	clusteradcsissuerlog.Info("default", "name", r.Name)

	if r.Spec.StatusCheckInterval == "" {
		r.Spec.StatusCheckInterval = "6h"
	}
	if r.Spec.RetryInterval == "" {
		r.Spec.RetryInterval = "1h"
	}
}

// +kubebuilder:webhook:verbs=create;update,path=/validate-adcs-certmanager-lcwsre-io-v1-clusteradcsissuer,mutating=false,failurePolicy=fail,groups=adcs.certmanager.lcwsre.io,resources=clusteradcsissuers,versions=v1,name=vclusteradcsissuer.adcs.certmanager.lcwsre.io,sideEffects=None,admissionReviewVersions=v1

var _ webhook.Validator = &ClusterAdcsIssuer{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateCreate() (admission.Warnings, error) {
	clusteradcsissuerlog.Info("validate create", "name", r.Name)
	return nil, r.validateClusterAdcsIssuer()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	clusteradcsissuerlog.Info("validate update", "name", r.Name)
	return nil, r.validateClusterAdcsIssuer()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdcsIssuer) ValidateDelete() (admission.Warnings, error) {
	clusteradcsissuerlog.Info("validate delete", "name", r.Name)
	return nil, nil
}

func (r *ClusterAdcsIssuer) validateClusterAdcsIssuer() error {
	var allErrs field.ErrorList

	// Validate RetryInterval
	if _, err := time.ParseDuration(r.Spec.RetryInterval); err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("retryInterval"), r.Spec.RetryInterval, err.Error()))
	}

	// Validate Status Check Interval
	if _, err := time.ParseDuration(r.Spec.StatusCheckInterval); err != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("statusCheckInterval"), r.Spec.StatusCheckInterval, err.Error()))
	}

	// Validate URL - must be valid http or https URL
	re := regexp.MustCompile(`^(http|https)://[\w\-_.]+(?:\.[\w\-_.]+)*(?::\d+)?(?:/[^\s]*)?$`)
	if !re.MatchString(r.Spec.URL) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("url"), r.Spec.URL, "Invalid URL format. Must be valid 'http://' or 'https://' URL."))
	}

	// Validate CA Bundle if provided - must be a valid PEM certificate
	if len(r.Spec.CABundle) > 0 {
		block, _ := pem.Decode(r.Spec.CABundle)
		if block == nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("caBundle"), "", "failed to decode PEM block"))
		} else if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("caBundle"), "", err.Error()))
		}
	}

	if len(allErrs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(
		schema.GroupKind{Group: "adcs.certmanager.lcwsre.io", Kind: "ClusterAdcsIssuer"},
		r.Name, allErrs)
}
