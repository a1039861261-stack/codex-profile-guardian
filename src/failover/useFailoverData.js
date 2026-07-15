import { useCallback, useEffect, useRef, useState } from "react";

const emptyPage = { items: [], page: { offset: 0, limit: 20, has_more: false } };

export function useFailoverData(client, refreshKey) {
  const [overview, setOverview] = useState(null);
  const [events, setEvents] = useState(emptyPage);
  const [hosts, setHosts] = useState({ schema_version: 1, checked_at: null, items: [] });
  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [initialError, setInitialError] = useState(null);
  const [refreshError, setRefreshError] = useState(null);
  const [eventsError, setEventsError] = useState(null);
  const [hostsError, setHostsError] = useState(null);
  const [pendingAction, setPendingAction] = useState(null);
  const requestRef = useRef(null);

  const applyOverview = useCallback((value) => {
    if (!value) return;
    setOverview(value);
    setSelectedGroupId(value.selected_group_id || value.group?.id || null);
  }, []);

  const load = useCallback(async ({ background = false, groupId, initial = false } = {}) => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    if (background) setRefreshing(true);
    else if (!overview) setLoading(true);
    try {
      const nextOverview = await client.getOverview({
        groupId: groupId ?? selectedGroupId,
        signal: controller.signal,
      });
      const nextGroupId = nextOverview?.selected_group_id || nextOverview?.group?.id || null;
      let nextEvents = emptyPage;
      let nextEventsError = null;
      let nextHosts = { schema_version: 1, checked_at: null, items: [] };
      let nextHostsError = null;
      try {
        nextHosts = await client.getHosts({ signal: controller.signal });
      } catch (error) {
        if (error?.name === "AbortError") throw error;
        nextHostsError = error;
      }
      if (nextGroupId) {
        try {
          nextEvents = await client.getEvents({
            groupId: nextGroupId,
            offset: 0,
            limit: 20,
            signal: controller.signal,
          });
        } catch (error) {
          if (error?.name === "AbortError") throw error;
          nextEvents = emptyPage;
          nextEventsError = error;
        }
      }
      applyOverview(nextOverview);
      setEvents(nextEvents || emptyPage);
      setEventsError(nextEventsError);
      setHosts(nextHosts || { schema_version: 1, checked_at: null, items: [] });
      setHostsError(nextHostsError);
      setInitialError(null);
      setRefreshError(null);
    } catch (error) {
      if (error?.name === "AbortError") return;
      if (!initial && overview) setRefreshError(error);
      else setInitialError(error);
    } finally {
      if (requestRef.current === controller) requestRef.current = null;
      setLoading(false);
      setRefreshing(false);
    }
  }, [applyOverview, client, overview, selectedGroupId]);

  useEffect(() => {
    setOverview(null);
    setEvents(emptyPage);
    setHosts({ schema_version: 1, checked_at: null, items: [] });
    setSelectedGroupId(null);
    setInitialError(null);
    setRefreshError(null);
    setEventsError(null);
    setHostsError(null);
    setLoading(true);
    load({ groupId: null, initial: true });
    return () => requestRef.current?.abort();
  }, [client, refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectGroup = useCallback((groupId) => {
    setSelectedGroupId(groupId);
    load({ groupId });
  }, [load]);

  const runMutation = useCallback(async (actionId, work) => {
    setPendingAction(actionId);
    setRefreshError(null);
    try {
      const result = await work();
      if (result?.overview) {
        applyOverview(result.overview);
        setInitialError(null);
        setRefreshError(null);
        const groupId = result.overview.selected_group_id || result.overview.group?.id;
        if (groupId) {
          try {
            const nextEvents = await client.getEvents({ groupId, offset: 0, limit: 20 });
            setEvents(nextEvents || emptyPage);
            setEventsError(null);
          } catch (error) {
            if (error?.name === "AbortError") throw error;
            setEvents(emptyPage);
            setEventsError(error);
          }
        } else {
          setEvents(emptyPage);
          setEventsError(null);
        }
      } else {
        await load({ background: true });
      }
      return result;
    } catch (error) {
      throw error;
    } finally {
      setPendingAction(null);
    }
  }, [applyOverview, client, load]);

  const loadMoreEvents = useCallback(async () => {
    if (!selectedGroupId || !events?.page?.has_more || pendingAction === "events") return;
    setPendingAction("events");
    try {
      const next = await client.getEvents({
        groupId: selectedGroupId,
        offset: events.items.length,
        limit: events.page.limit || 20,
      });
      setEvents({
        items: [...events.items, ...(next?.items || [])],
        page: next?.page || { offset: events.items.length, limit: 20, has_more: false },
      });
      setEventsError(null);
    } catch (error) {
      setEventsError(error);
    } finally {
      setPendingAction(null);
    }
  }, [client, events, pendingAction, selectedGroupId]);

  const refreshHosts = useCallback(async () => {
    if (pendingAction) return;
    setPendingAction("hosts");
    try {
      const nextHosts = await client.refreshHosts();
      setHosts(nextHosts || { schema_version: 1, checked_at: null, items: [] });
      setHostsError(null);
    } catch (error) {
      setHostsError(error);
    } finally {
      setPendingAction(null);
    }
  }, [client, pendingAction]);

  return {
    overview,
    events,
    hosts,
    loading,
    refreshing,
    initialError,
    refreshError,
    eventsError,
    hostsError,
    pendingAction,
    selectedGroupId,
    selectGroup,
    refresh: () => load({ background: true }),
    runMutation,
    loadMoreEvents,
    refreshHosts,
  };
}
