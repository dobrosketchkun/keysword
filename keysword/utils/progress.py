"""Enhanced progress display utilities."""

import time
import sys


class EnhancedProgressBar:
    """Enhanced progress bar with ETA and speed display."""
    
    def __init__(self, total, desc="Progress", unit="item", use_tqdm=True):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            desc: Description text
            unit: Unit name for items
            use_tqdm: Try to use tqdm if available
        """
        self.total = total
        self.desc = desc
        self.unit = unit
        self.current = 0
        self.start_time = None
        self.pbar = None
        self.use_tqdm = use_tqdm
        
        if use_tqdm:
            try:
                from tqdm import tqdm
                self.pbar = tqdm(
                    total=total,
                    desc=desc,
                    unit=unit,
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
                )
                self.using_tqdm = True
            except ImportError:
                self.using_tqdm = False
                self._init_fallback()
        else:
            self.using_tqdm = False
            self._init_fallback()
    
    def _init_fallback(self):
        """Initialize fallback progress display."""
        try:
            import progressbar
            self.pbar = progressbar.ProgressBar(max_value=self.total, redirect_stdout=True)
            self.using_progressbar = True
        except ImportError:
            self.using_progressbar = False
            self.start_time = time.time()
    
    def __enter__(self):
        """Context manager entry."""
        if not self.start_time:
            self.start_time = time.time()
        return self
    
    def __exit__(self, *args):
        """Context manager exit."""
        self.close()
    
    def update(self, n=1):
        """
        Update progress.
        
        Args:
            n: Number of items to increment
        """
        self.current += n
        
        if self.using_tqdm:
            self.pbar.update(n)
        elif hasattr(self, 'using_progressbar') and self.using_progressbar:
            self.pbar.update(self.current)
        else:
            # Simple text-based progress
            self._update_simple()
    
    def _update_simple(self):
        """Simple text-based progress update."""
        elapsed = time.time() - self.start_time
        percent = (self.current / self.total) * 100
        rate = self.current / elapsed if elapsed > 0 else 0
        
        # Estimate time remaining
        if rate > 0:
            remaining = (self.total - self.current) / rate
            eta = self._format_time(remaining)
        else:
            eta = "?"
        
        # Build progress string
        bar_width = 30
        filled = int(bar_width * self.current / self.total)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        progress_str = f"\r{self.desc}: |{bar}| {self.current}/{self.total} [{percent:.1f}%] "
        progress_str += f"[{self._format_time(elapsed)}<{eta}, {rate:.2f} {self.unit}/s]"
        
        sys.stdout.write(progress_str)
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write("\n")
    
    def _format_time(self, seconds):
        """Format seconds as human-readable time."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            mins = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{mins}m{secs:02d}s"
        else:
            hours = int(seconds / 3600)
            mins = int((seconds % 3600) / 60)
            return f"{hours}h{mins:02d}m"
    
    def set_postfix(self, **kwargs):
        """
        Set postfix info.
        
        Args:
            **kwargs: Key-value pairs to display
        """
        if self.using_tqdm:
            self.pbar.set_postfix(**kwargs)
    
    def close(self):
        """Close and finalize progress bar."""
        if self.using_tqdm and self.pbar:
            self.pbar.close()
        elif hasattr(self, 'using_progressbar') and self.using_progressbar and self.pbar:
            # progressbar doesn't need explicit close
            pass
        elif not self.using_tqdm:
            if self.current < self.total:
                sys.stdout.write("\n")
            
            # Show final stats
            if self.start_time:
                elapsed = time.time() - self.start_time
                rate = self.current / elapsed if elapsed > 0 else 0
                print(f"Completed {self.current} {self.unit}(s) in {self._format_time(elapsed)} ({rate:.2f} {self.unit}/s)")

