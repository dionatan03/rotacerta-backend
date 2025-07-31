package internal

import "time"

// Retorna o timestamp UTC atual (evita bugs de timezone)
func Now() time.Time {
    return time.Now().UTC()
}
