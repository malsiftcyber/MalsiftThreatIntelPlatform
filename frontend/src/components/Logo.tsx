import React from 'react';

interface LogoProps {
  variant?: 'full' | 'text' | 'icon';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

export default function Logo({ variant = 'full', size = 'md', className = '' }: LogoProps) {
  const sizeClasses = {
    sm: 'h-6',
    md: 'h-8',
    lg: 'h-12',
    xl: 'h-16',
  };

  const logoSrc = {
    full: '/logo.svg',
    text: '/logo-text.svg',
    icon: '/favicon.svg',
  };

  return (
    <img
      src={logoSrc[variant]}
      alt="Malsift"
      className={`${sizeClasses[size]} ${className}`}
    />
  );
}
